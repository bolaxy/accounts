package keystore

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bolaxy/common"
	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/bolaxy/accounts"
)

// Minimum amount of time between cache reloads. This limit applies if the platform does
// not support change notifications. It also applies if the keystore directory does not
// exist yet, the code will attempt to create a watcher at most this often.
const minReloadInterval = 2 * time.Second

type accountsByURL []accounts.Account

func (s accountsByURL) Len() int           { return len(s) }
func (s accountsByURL) Less(i, j int) bool { return s[i].URL.Cmp(s[j].URL) < 0 }
func (s accountsByURL) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// AmbiguousAddrError is returned when attempting to unlock
// an address for which more than one file exists.
type AmbiguousAddrError struct {
	Addr    common.Address
	Matches []accounts.Account
}

func (err *AmbiguousAddrError) Error() string {
	files := ""
	for i, a := range err.Matches {
		files += a.URL.Path
		if i < len(err.Matches)-1 {
			files += ", "
		}
	}
	return fmt.Sprintf("multiple keys match address (%s)", files)
}

// accountCache is a live index of all accounts in the keystore.
type accountCache struct {
	keydir   string
	watcher  *watcher
	mu       sync.Mutex
	all      accountsByURL
	byAddr   map[common.Address][]accounts.Account
	byAlias  map[string]accounts.Account
	throttle *time.Timer
	notify   chan struct{}
	fileC    fileCache
	logger   *logrus.Entry
}

func newAccountCache(keydir string, log *logrus.Entry) (*accountCache, chan struct{}) {
	ac := &accountCache{
		keydir:  keydir,
		byAddr:  make(map[common.Address][]accounts.Account),
		byAlias: make(map[string]accounts.Account),
		notify:  make(chan struct{}, 1),
		fileC:   fileCache{all: mapset.NewThreadUnsafeSet(), logger: log},
		logger:  log,
	}
	ac.watcher = newWatcher(ac, log)
	return ac, ac.notify
}

func (ac *accountCache) accounts() []accounts.Account {
	ac.maybeReload()
	ac.mu.Lock()
	defer ac.mu.Unlock()
	cpy := make([]accounts.Account, len(ac.all))
	copy(cpy, ac.all)
	return cpy
}

func (ac *accountCache) hasAddress(addr common.Address) bool {
	ac.maybeReload()
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return len(ac.byAddr[addr]) > 0
}

func (ac *accountCache) hasAlias(alias string) bool {
	ac.maybeReload()
	ac.mu.Lock()
	defer ac.mu.Unlock()
	_, ok := ac.byAlias[alias]
	return ok
}

func (ac *accountCache) add(newAccount accounts.Account) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if _, ok := ac.byAlias[newAccount.Alias]; ok {
		return
	}

	i := sort.Search(len(ac.all), func(i int) bool { return ac.all[i].URL.Cmp(newAccount.URL) >= 0 })
	if i < len(ac.all) && ac.all[i] == newAccount {
		return
	}
	// newAccount is not in the cache.
	ac.all = append(ac.all, accounts.Account{})
	copy(ac.all[i+1:], ac.all[i:])
	ac.all[i] = newAccount
	ac.byAddr[newAccount.Address] = append(ac.byAddr[newAccount.Address], newAccount)
	ac.byAlias[newAccount.Alias] = newAccount
}

// note: removed needs to be unique here (i.e. both File and Address must be set).
func (ac *accountCache) delete(removed accounts.Account) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.all = removeAccount(ac.all, removed)
	if ba := removeAccount(ac.byAddr[removed.Address], removed); len(ba) == 0 {
		delete(ac.byAddr, removed.Address)
	} else {
		ac.byAddr[removed.Address] = ba
	}
}

func (ac *accountCache) deleteByAlias(alias string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	removed, ok := ac.byAlias[alias]
	if !ok {
		return
	}

	ac.delete(removed)
	delete(ac.byAlias, alias)
}

// deleteByFile removes an account referenced by the given path.
func (ac *accountCache) deleteByFile(path string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	i := sort.Search(len(ac.all), func(i int) bool { return ac.all[i].URL.Path >= path })

	if i < len(ac.all) && ac.all[i].URL.Path == path {
		removed := ac.all[i]
		ac.all = append(ac.all[:i], ac.all[i+1:]...)
		if ba := removeAccount(ac.byAddr[removed.Address], removed); len(ba) == 0 {
			delete(ac.byAddr, removed.Address)
		} else {
			ac.byAddr[removed.Address] = ba
		}
	}
}

func removeAccount(slice []accounts.Account, elem accounts.Account) []accounts.Account {
	for i := range slice {
		if slice[i] == elem {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func (ac *accountCache) findByAlias(alias string) *accounts.Account {
	if match, ok := ac.byAlias[alias]; ok {
		return &match
	}

	return nil
}

// find returns the cached account for address if there is a unique match.
// The exact matching rules are explained by the documentation of accounts.Account.
// Callers must hold ac.mu.
func (ac *accountCache) find(a accounts.Account) (accounts.Account, error) {
	if match, ok := ac.byAlias[a.Alias]; ok {
		return match, nil
	}

	// Limit search to address candidates if possible.
	matches := ac.all
	if (a.Address != common.Address{}) {
		matches = ac.byAddr[a.Address]
	}
	if a.URL.Path != "" {
		// If only the basename is specified, complete the path.
		if !strings.ContainsRune(a.URL.Path, filepath.Separator) {
			a.URL.Path = filepath.Join(ac.keydir, a.URL.Path)
		}
		for i := range matches {
			if matches[i].URL == a.URL {
				return matches[i], nil
			}
		}
		if (a.Address == common.Address{}) {
			return accounts.Account{}, ErrNoMatch
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return accounts.Account{}, ErrNoMatch
	default:
		err := &AmbiguousAddrError{Addr: a.Address, Matches: make([]accounts.Account, len(matches))}
		copy(err.Matches, matches)
		sort.Sort(accountsByURL(err.Matches))
		return accounts.Account{}, err
	}
}

func (ac *accountCache) maybeReload() {
	ac.mu.Lock()

	if ac.watcher.running {
		ac.mu.Unlock()
		return // A watcher is running and will keep the cache up-to-date.
	}
	if ac.throttle == nil {
		ac.throttle = time.NewTimer(0)
	} else {
		select {
		case <-ac.throttle.C:
		default:
			ac.mu.Unlock()
			return // The cache was reloaded recently.
		}
	}
	// No watcher running, start it.
	ac.watcher.start()
	ac.throttle.Reset(minReloadInterval)
	ac.mu.Unlock()
	ac.scanAccounts()
}

func (ac *accountCache) close() {
	ac.mu.Lock()
	ac.watcher.close()
	if ac.throttle != nil {
		ac.throttle.Stop()
	}
	if ac.notify != nil {
		close(ac.notify)
		ac.notify = nil
	}
	ac.mu.Unlock()
}

// scanAccounts checks if any changes have occurred on the filesystem, and
// updates the account cache accordingly
func (ac *accountCache) scanAccounts() error {
	// Scan the entire folder metadata for file changes
	creates, deletes, updates, err := ac.fileC.scan(ac.keydir)
	if err != nil {
		ac.logger.WithError(err).Debug("Failed to reload keystore contents")
		return err
	}
	if creates.Cardinality() == 0 && deletes.Cardinality() == 0 && updates.Cardinality() == 0 {
		return nil
	}
	// Create a helper method to scan the contents of the key files
	var (
		buf = new(bufio.Reader)
		key struct {
				Address string `json:"address"`
			}
	)
	readAccount := func(filePath string) *accounts.Account {
		alias := strings.Split(path.Base(filePath), ".")
		fd, err := os.Open(filePath)
		if err != nil {
			ac.logger.Trace("Failed to open keystore file", "path", filePath, "err", err)
			return nil
		}
		defer fd.Close()
		buf.Reset(fd)
		// Parse the address.
		key.Address = ""
		err = json.NewDecoder(buf).Decode(&key)
		addr := common.HexToAddress(key.Address)
		switch {
		case err != nil:
			ac.logger.Debug("Failed to decode keystore key", "path", filePath, "err", err)
		case (addr == common.Address{}):
			ac.logger.Debug("Failed to decode keystore key", "path", filePath, "err", "missing or zero address")
		default:
			return &accounts.Account{
				Alias:   alias[0],
				Address: addr,
				URL:     accounts.URL{Scheme: Scheme, Path: filePath},
			}
		}
		return nil
	}
	// Process all the file diffs
	start := time.Now()

	for _, p := range creates.ToSlice() {
		if a := readAccount(p.(string)); a != nil {
			ac.add(*a)
		}
	}
	for _, p := range deletes.ToSlice() {
		ac.deleteByFile(p.(string))
	}
	for _, p := range updates.ToSlice() {
		path := p.(string)
		ac.deleteByFile(path)
		if a := readAccount(path); a != nil {
			ac.add(*a)
		}
	}
	end := time.Now()

	select {
	case ac.notify <- struct{}{}:
	default:
	}
	ac.logger.Trace("Handled keystore changes", "time", end.Sub(start))
	return nil
}
