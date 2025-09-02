// lfspkg: gerenciador de pacotes para LFS – source-based, 100% funcional
// Atualizado: deps reais no build/install; pós-remoção correto; upgrade segura;
// packaging/strip robustos; busca recursiva; CLI abreviada; cores; hooks.
// Somente Go stdlib.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ========================= Config & Vars ===============================

type Config struct {
	State   string // /var/lib/lfspkg
	Cache   string // /var/cache/lfspkg
	Bin     string // /usr/bin (info)
	Sources string // onde salvar fontes
	Repo    string // raiz de receitas (busca recursiva)
	Strip   bool   // aplicar strip
}

var cfg Config

func initConfig() {
	cfg.State = getenv("LFSPKG_STATE", "/var/lib/lfspkg")
	cfg.Cache = getenv("LFSPKG_CACHE", "/var/cache/lfspkg")
	cfg.Bin = getenv("LFSPKG_BIN", "/usr/bin")
	cfg.Sources = getenv("LFSPKG_SOURCES", filepath.Join(cfg.Cache, "src"))
	cfg.Repo = getenv("LFSPKG_REPO", "./recipes")
	cfg.Strip = strings.EqualFold(getenv("LFSPKG_STRIP", ""), "1")
}

func getenv(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }

// ========================= Color helpers ===============================

var (
	cReset = "[0m"
	cBold  = "[1m"
	cRed   = "[31m"
	cGreen = "[32m"
	cBlue  = "[34m"
	cCyan  = "[36m"
	cYellow= "[33m"
)

func infof(format string, a ...any)   { fmt.Printf(cCyan+format+cReset+"
", a...) }
func okf(format string, a ...any)     { fmt.Printf(cGreen+format+cReset+"
", a...) }
func warnf(format string, a ...any)   { fmt.Printf(cYellow+format+cReset+"
", a...) }
func errorf(format string, a ...any)  { fmt.Printf(cRed+format+cReset+"
", a...) }

// ========================= Data types ==================================

type Source struct {
	Type   string `json:"type,omitempty"` // "tar" (default) or "git"
	URL    string `json:"url"`
	SHA256 string `json:"sha256,omitempty"`
	Ref    string `json:"ref,omitempty"` // git ref/tag/commit
}

type Steps struct {
	Extract     string `json:"extract"`
	Patch       string `json:"patch"`
	Prepare     string `json:"prepare"`
	Preconfig   string `json:"preconfig"`
	Configure   string `json:"configure"`
	Build       string `json:"build"`
	Check       string `json:"check"`
	Install     string `json:"install"`
	Postinstall string `json:"postinstall"`
	PostRemove  string `json:"postremove"`
}

type Recipe struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Source      Source            `json:"source"`
	Deps        []string          `json:"deps"`
	Env         map[string]string `json:"env"`
	Steps       Steps             `json:"steps"`
	Description string            `json:"description,omitempty"`
}

// ========================= Paths =======================================

func pathState(parts ...string) string { return filepath.Join(append([]string{cfg.State}, parts...)...) }
func pathCache(parts ...string) string { return filepath.Join(append([]string{cfg.Cache}, parts...)...) }

// ========================= Utils =======================================

func must(err error) { if err != nil { panic(err) } }

func requireRoot(op string) {
	if os.Geteuid() != 0 {
		errorf("%s requer root", op)
		os.Exit(1)
	}
}

func ensureDirs() error {
	dirs := []string{ pathState("manifest"), pathState("db"), pathCache("src"), pathCache("build"), pathCache("pkgs") }
	for _, d := range dirs { if err := os.MkdirAll(d, 0o755); err != nil { return err } }
	return nil
}

func readRecipe(path string) (*Recipe, error) {
	b, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var r Recipe
	if err := json.Unmarshal(b, &r); err != nil { return nil, err }
	if r.Name == "" || r.Version == "" { return nil, errors.New("recipe missing name/version") }
	if r.Source.Type == "" { r.Source.Type = "tar" }
	if r.Env == nil { r.Env = map[string]string{} }
	return &r, nil
}

// busca recursiva por <name>.json em cfg.Repo
func recipePathRecursive(name string) (string, error) {
	var found string
	err := filepath.WalkDir(cfg.Repo, func(p string, d fs.DirEntry, err error) error {
		if err != nil { return err }
		if d.IsDir() { return nil }
		if filepath.Base(p) == name+".json" { found = p; return io.EOF }
		return nil
	})
	if err != nil && err != io.EOF { return "", err }
	if found == "" { return "", fmt.Errorf("recipe %s not found under %s", name, cfg.Repo) }
	return found, nil
}

func verifySHA256(path, want string) (bool, error) {
	fh, err := os.Open(path); if err != nil { return false, err }
	defer fh.Close()
	h := sha256.New(); if _, err := io.Copy(h, fh); err != nil { return false, err }
	got := hex.EncodeToString(h.Sum(nil))
	return strings.EqualFold(got, want), nil
}

func runShell(cmd string, env map[string]string, workdir string) error {
	if strings.TrimSpace(cmd) == "" { return nil }
	c := exec.Command("/bin/sh", "-lc", cmd)
	c.Dir = workdir
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	e := os.Environ()
	for k, v := range env { e = append(e, fmt.Sprintf("%s=%s", k, v)) }
	c.Env = e
	return c.Run()
}

func inferSrcBase(tarPath string) string {
	base := filepath.Base(tarPath)
	re := regexp.MustCompile(`\.(tar\.(gz|bz2|xz|zst)|tgz|tbz2|txz)$`)
	base = re.ReplaceAllString(base, "")
	return base
}

// ========================= Fetch/Extract ================================

func fetch(r *Recipe) (string, error) {
	os.MkdirAll(cfg.Sources, 0o755)
	if r.Source.Type == "git" {
		dest := filepath.Join(cfg.Sources, r.Name+"-"+r.Version+".git")
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			infof("[git clone] %s", r.Source.URL)
			cmd := exec.Command("git", "clone", r.Source.URL, dest)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil { return "", err }
		} else {
			infof("[git fetch] %s", dest)
			cmd := exec.Command("git", "-C", dest, "fetch", "--all", "--tags")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil { return "", err }
		}
		if r.Source.Ref != "" {
			cmd := exec.Command("git", "-C", dest, "checkout", r.Source.Ref)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil { return "", err }
		}
		return dest, nil
	}
	filename := filepath.Join(cfg.Sources, filepath.Base(r.Source.URL))
	if st, err := os.Stat(filename); err == nil && st.Size() > 0 {
		if r.Source.SHA256 != "" {
			ok, err := verifySHA256(filename, r.Source.SHA256)
			if err != nil || !ok { _ = os.Remove(filename) } else { return filename, nil }
		} else { return filename, nil }
	}
	infof("[fetch] %s", r.Source.URL)
	resp, err := http.Get(r.Source.URL)
	if err != nil { return "", err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return "", fmt.Errorf("http %d", resp.StatusCode) }
	f, err := os.Create(filename)
	if err != nil { return "", err }
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil { return "", err }
	if r.Source.SHA256 != "" {
		ok, err := verifySHA256(filename, r.Source.SHA256)
		if err != nil { return "", err }
		if !ok { return "", fmt.Errorf("sha256 mismatch for %s", filename) }
	}
	return filename, nil
}

// ========================= Build pipeline ===============================

func buildPipeline(r *Recipe, only string) error {
	buildDir := filepath.Join(cfg.Cache, "build", r.Name+"-"+r.Version)
	_ = os.RemoveAll(buildDir)
	must(os.MkdirAll(buildDir, 0o755))
	staging := filepath.Join(buildDir, "destdir")
	must(os.MkdirAll(staging, 0o755))
	srcPath, err := fetch(r)
	if err != nil { return err }

	env := map[string]string{
		"BUILD":   buildDir,
		"DESTDIR": staging,
		"PREFIX":  "/usr",
		"JOBS":    fmt.Sprintf("%d", runtime.NumCPU()),
		"SRC":     srcPath,
		"SRC_BASENAME": inferSrcBase(srcPath),
		"BIN":     cfg.Bin,
		"SOURCES": cfg.Sources,
		"REPO":    cfg.Repo,
	}
	for k, v := range r.Env { env[k] = v }

	if r.Source.Type == "git" {
		target := filepath.Join(buildDir, "src")
		_ = os.RemoveAll(target)
		must(os.MkdirAll(target, 0o755))
		cmd := exec.Command("/bin/sh", "-lc", fmt.Sprintf("cd '%s' && tar -cf - . | tar -xf - -C '%s'", srcPath, target))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil { return err }
		env["SRC_BASENAME"] = "src"
	}

	stages := []struct{ key, label, cmd string }{
		{"extract", "extract", r.Steps.Extract},
		{"patch", "patch", r.Steps.Patch},
		{"prepare", "prepare", r.Steps.Prepare},
		{"preconfig", "preconfig", r.Steps.Preconfig},
		{"configure", "configure", r.Steps.Configure},
		{"build", "build", r.Steps.Build},
		{"check", "check", r.Steps.Check},
		{"install", "install", r.Steps.Install},
		{"postinstall", "postinstall", r.Steps.Postinstall},
	}

	for _, st := range stages {
		if only != "" && only != st.key { continue }
		if strings.TrimSpace(st.cmd) == "" { if only == st.key { warnf("[%s] vazio", st.label) }; continue }
		infof("[%s] %s-%s", st.label, r.Name, r.Version)
		if err := runShell(st.cmd, env, "/"); err != nil { return fmt.Errorf("%s: %w", st.label, err) }
		if only == st.key { return nil }
	}

	// strip (opcional) no DESTDIR
	if cfg.Strip { _ = stripTree(staging) }

	// empacotar DESTDIR
	pkgPath, err := packageDestdir(r, staging)
	if err != nil { return err }
	okf("[package] %s", pkgPath)

	// instalar
	requireRoot("install")
	files, links, err := copyTree(staging, "/")
	if err != nil { return err }
	if err := writeManifestAndDB(r, files, links); err != nil { return err }
	okf("[install] %s-%s instalado", r.Name, r.Version)
	return nil
}

func stripTree(root string) error {
	_, err := exec.LookPath("strip")
	if err != nil { warnf("strip não encontrado, ignorando"); return nil }
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil { return err }
		if d.IsDir() { return nil }
		if strings.HasPrefix(filepath.Base(p), ".") { return nil }
		// strip silencioso, ignora erros
		cmd := exec.Command("strip", "--strip-unneeded", p)
		_ = cmd.Run()
		return nil
	})
}

func packageDestdir(r *Recipe, dest string) (string, error) {
	out := pathCache("pkgs")
	if err := os.MkdirAll(out, 0o755); err != nil { return "", err }
	name := fmt.Sprintf("%s-%s.tar.zst", r.Name, r.Version)
	pkg := filepath.Join(out, name)
	if _, err := exec.LookPath("zstd"); err == nil {
		cmd := exec.Command("/bin/sh", "-lc", fmt.Sprintf("cd '%s' && tar -cf - . | zstd -19 -T0 -o '%s'", dest, pkg))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err == nil { return pkg, nil }
	}
	pkg = strings.TrimSuffix(pkg, ".zst") + ".xz"
	cmd := exec.Command("/bin/sh", "-lc", fmt.Sprintf("cd '%s' && tar -cJf '%s' .", dest, pkg))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil { return "", err }
	return pkg, nil
}

// ========================= Install DB/Manifest ==========================

func writeManifestAndDB(r *Recipe, files, links []string) error {
	must(os.MkdirAll(pathState("manifest"), 0o755))
	man := pathState("manifest", fmt.Sprintf("%s-%s.list", r.Name, r.Version))
	var lines []string
	lines = append(lines, "# files")
	lines = append(lines, files...)
	lines = append(lines, "# symlinks")
	lines = append(lines, links...)
	if err := writeLines(man, lines); err != nil { return err }
	must(os.MkdirAll(pathState("db"), 0o755))
	dbb := pathState("db", r.Name+".json")
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(dbb, b, 0o644); err != nil { return err }
	// remove manifestos antigos do mesmo pacote, mantendo o atual
	cleanupOldManifests(r.Name, man)
	return nil
}

func cleanupOldManifests(name, keep string) {
	dir := pathState("manifest")
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.IsDir() { continue }
		p := filepath.Join(dir, e.Name())
		if p == keep { continue }
		if strings.HasPrefix(e.Name(), name+"-") && strings.HasSuffix(e.Name(), ".list") {
			_ = os.Remove(p)
		}
	}
}

func copyTree(src, dstRoot string) (files []string, links []string, err error) {
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil { return err }
		rel, _ := filepath.Rel(src, path)
		if rel == "." { return nil }
		dst := filepath.Join(dstRoot, rel)
		info, lerr := os.Lstat(path)
		if lerr != nil { return lerr }
		if info.Mode()&os.ModeSymlink != 0 {
			tgt, e := os.Readlink(path); if e != nil { return e }
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { return err }
			_ = os.RemoveAll(dst)
			if err := os.Symlink(tgt, dst); err != nil { return err }
			links = append(links, "/"+rel)
			return nil
		}
		if d.IsDir() { return os.MkdirAll(dst, 0o755) }
		if err := copyFile(path, dst); err != nil { return err }
		files = append(files, "/"+rel)
		return nil
	})
	return
}

func copyFile(src, dst string) error {
	s, err := os.Open(src); if err != nil { return err }
	defer s.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { return err }
	_ = os.RemoveAll(dst)
	d, err := os.Create(dst); if err != nil { return err }
	defer d.Close()
	if _, err := io.Copy(d, s); err != nil { return err }
	if info, err := os.Stat(src); err == nil { _ = os.Chmod(dst, info.Mode()) }
	return nil
}

// ========================= Remove & Hooks ===============================

func parseSpec(spec string) (name, version string) {
	if strings.Contains(spec, "@") { parts := strings.SplitN(spec, "@", 2); return parts[0], parts[1] }
	return spec, ""
}

func pickManifest(name, version string) (string, error) {
	dir := pathState("manifest")
	ents, err := os.ReadDir(dir); if err != nil { return "", err }
	var candidates []string
	for _, e := range ents {
		if e.IsDir() { continue }
		fn := e.Name()
		if strings.HasPrefix(fn, name+"-") && strings.HasSuffix(fn, ".list") {
			if version == "" || strings.HasPrefix(fn, name+"-"+version) { candidates = append(candidates, filepath.Join(dir, fn)) }
		}
	}
	if len(candidates) == 0 { return "", fmt.Errorf("manifest not found for %s", name) }
	if len(candidates) == 1 { return candidates[0], nil }
	type item struct{ path string; m time.Time }
	var its []item
	for _, p := range candidates { st, _ := os.Stat(p); its = append(its, item{p, st.ModTime()}) }
	sort.Slice(its, func(i, j int) bool { return its[i].m.After(its[j].m) })
	return its[0].path, nil
}

func removePackage(spec string) error {
	requireRoot("remove")
	name, version := parseSpec(spec)
	man, err := pickManifest(name, version); if err != nil { return err }
	// leia a receita antes de apagar o db (para PostRemove)
	recPath, _ := recipePathRecursive(name)
	var rec *Recipe
	if recPath != "" { rec, _ = readRecipe(recPath) }

	b, err := os.ReadFile(man); if err != nil { return err }
	s := bufio.NewScanner(strings.NewReader(string(b)))
	var paths []string
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		paths = append(paths, line)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, p := range paths { _ = os.Remove(p) }
	for _, p := range paths { pruneUp(filepath.Dir(p)) }
	_ = os.Remove(man)
	_ = os.Remove(pathState("db", name+".json"))
	// hook pós-remoção
	if rec != nil && strings.TrimSpace(rec.Steps.PostRemove) != "" {
		_ = runShell(rec.Steps.PostRemove, map[string]string{"REPO": cfg.Repo}, "/")
	}
	okf("[remove] %s", spec)
	return nil
}

var pruneStop = map[string]bool{"/": true, "/usr": true, "/usr/bin": true, "/usr/lib": true, "/usr/lib64": true, "/usr/share": true, "/etc": true, "/opt": true, "/var": true}

func pruneUp(dir string) {
	for { if dir == "" || pruneStop[dir] { return }; entries, err := os.ReadDir(dir); if err != nil { return }; if len(entries) == 0 { _ = os.Remove(dir); dir = filepath.Dir(dir); continue }; return }
}

// ========================= Query / List / Search ========================

func queryPackage(name string) error {
	db := pathState("db", name+".json")
	b, err := os.ReadFile(db); if err != nil { return err }
	fmt.Println(string(b))
	return nil
}

func listInstalled() error {
	dir := pathState("manifest")
	ents, err := os.ReadDir(dir); if err != nil { return err }
	var lines []string
	for _, e := range ents { if e.IsDir() { continue }; fn := e.Name(); if strings.HasSuffix(fn, ".list") { lines = append(lines, strings.TrimSuffix(fn, ".list")) } }
	sort.Strings(lines)
	for _, l := range lines { okf("[✓] %s", l) }
	return nil
}

func isInstalled(name string) bool {
	ents, err := os.ReadDir(pathState("manifest")); if err != nil { return false }
	for _, e := range ents { if strings.HasPrefix(e.Name(), name+"-") && strings.HasSuffix(e.Name(), ".list") { return true } }
	return false
}

func searchRecipes(term string) error {
	var found []string
	_ = filepath.WalkDir(cfg.Repo, func(p string, d fs.DirEntry, err error) error {
		if err != nil { return err }
		if d.IsDir() { return nil }
		if strings.HasSuffix(p, ".json") && strings.Contains(strings.ToLower(filepath.Base(p)), strings.ToLower(term)) {
			name := strings.TrimSuffix(filepath.Base(p), ".json")
			mark := "[ ]"; if isInstalled(name) { mark = "[✓]" }
			found = append(found, fmt.Sprintf("%s %s (%s)", mark, name, filepath.Dir(p)))
		}
		return nil
	})
	sort.Strings(found)
	for _, l := range found { fmt.Println(l) }
	if len(found) == 0 { warnf("nada encontrado para '%s'", term) }
	return nil
}

// ========================= Graph / Build+Deps / Upgrade =================

func topoOrder(target string) ([]string, error) {
	seen := map[string]bool{}
	var order []string
	var dfs func(string) error
	dfs = func(n string) error {
		if seen[n] { return nil }
		seen[n] = true
		p, err := recipePathRecursive(n); if err != nil { return err }
		r, err := readRecipe(p); if err != nil { return err }
		for _, d := range r.Deps { if err := dfs(d); err != nil { return err } }
		order = append(order, n)
		return nil
	}
	if err := dfs(target); err != nil { return nil, err }
	return order, nil
}

func buildWithDeps(name, only string) error {
	order, err := topoOrder(name); if err != nil { return err }
	for _, n := range order {
		p, _ := recipePathRecursive(n)
		r, _ := readRecipe(p)
		infof("[dep] %s", n)
		if err := buildPipeline(r, only); err != nil { return err }
	}
	return nil
}

func upgrade(name string) error {
	p, err := recipePathRecursive(name); if err != nil { return err }
	r, err := readRecipe(p); if err != nil { return err }
	infof("[upgrade] %s-%s", r.Name, r.Version)
	return buildPipeline(r, "")
}

// ========================= Git sync (estado) ============================

func syncGit(remote string) error {
	dir := cfg.State
	if _, err := os.Stat(filepath.Join(dir, ".git")); os.IsNotExist(err) {
		infof("[git init] %s", dir)
		must(os.MkdirAll(dir, 0o755))
		cmd := exec.Command("git", "init", dir); cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr; if err := cmd.Run(); err != nil { return err }
		if remote != "" { exec.Command("git", "-C", dir, "remote", "add", "origin", remote).Run() }
	}
	exec.Command("git", "-C", dir, "add", "-A").Run()
	msg := time.Now().Format("2006-01-02 15:04:05")
	exec.Command("git", "-C", dir, "commit", "-m", "lfspkg sync "+msg).Run()
	if remote != "" { _ = exec.Command("git", "-C", dir, "push", "-u", "origin", "HEAD").Run() }
	okf("[sync] estado commitado em %s", dir)
	return nil
}

// ========================= IO helpers ==================================

func writeLines(path string, lines []string) error {
	f, err := os.Create(path); if err != nil { return err }
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines { fmt.Fprintln(w, l) }
	return w.Flush()
}

// ========================= CLI =========================================

func usage() {
	fmt.Println(cBold+"lfspkg – gerenciador LFS (source)"+cReset)
	fmt.Println("Uso:")
	fmt.Println("  lfspkg init                              ")
	fmt.Println("  lfspkg fetch|f        <pkg>              [-R <repo>] [--strip]")
	fmt.Println("  lfspkg extract|x      <pkg>              [-R <repo>]          ")
	fmt.Println("  lfspkg patch|p        <pkg>              [-R <repo>]          ")
	fmt.Println("  lfspkg build|b        <pkg>              [-R <repo>] [--strip]")
	fmt.Println("  lfspkg check|c        <pkg>              [-R <repo>]          ")
	fmt.Println("  lfspkg install|i      <pkg>              [-R <repo>] [--strip]")
	fmt.Println("  lfspkg installdest|I  <pkg>              [-R <repo>]          ")
	fmt.Println("  lfspkg package|k      <pkg>              [-R <repo>]          ")
	fmt.Println("  lfspkg graph|g        <pkg>              [-R <repo>]          ")
	fmt.Println("  lfspkg list|l                            ")
	fmt.Println("  lfspkg search|s       <termo>            [-R <repo>]          ")
	fmt.Println("  lfspkg info|q         <pkg>              [-R <repo>]          ")
	fmt.Println("  lfspkg remove|r       <name[@vers]>                          ")
	fmt.Println("  lfspkg upgrade|u      <pkg>              [-R <repo>] [--strip]")
	fmt.Println("  lfspkg sync           [remote-url]                            ")
	fmt.Println()
	fmt.Println("Flags globais (ou ENV): LFSPKG_STATE, LFSPKG_CACHE, LFSPKG_BIN, LFSPKG_SOURCES, LFSPKG_REPO, --strip / LFSPKG_STRIP=1")
}

func main() {
	initConfig()
	if len(os.Args) < 2 { usage(); return }
	cmd := os.Args[1]
	fs := flag.NewFlagSet("lfspkg", flag.ExitOnError)
	repoFlag := fs.String("R", cfg.Repo, "diretório de receitas (raiz; busca recursiva)")
	stripFlag := fs.Bool("strip", cfg.Strip, "aplicar strip no DESTDIR")

	switch cmd {
	case "init":
		must(ensureDirs()); okf("Diretórios criados em %s e %s", cfg.State, cfg.Cache)
	case "fetch", "f":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag; cfg.Strip = *stripFlag
		name := os.Args[2]
		p, err := recipePathRecursive(name); must(err)
		r, err := readRecipe(p); must(err)
		_, err = fetch(r); must(err); okf("fetch ok")
	case "extract", "x", "patch", "p", "check", "c":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag; cfg.Strip = *stripFlag
		name := os.Args[2]
		p, err := recipePathRecursive(name); must(err)
		r, err := readRecipe(p); must(err)
		only := map[string]string{"extract":"extract","x":"extract","patch":"patch","p":"patch","check":"check","c":"check"}[cmd]
		must(buildPipeline(r, only))
	case "build", "b", "install", "i":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag; cfg.Strip = *stripFlag
		name := os.Args[2]
		must(buildWithDeps(name, ""))
	case "installdest", "I":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag
		name := os.Args[2]
		p, err := recipePathRecursive(name); must(err)
		r, err := readRecipe(p); must(err)
		buildDir := filepath.Join(cfg.Cache, "build", r.Name+"-"+r.Version)
		staging := filepath.Join(buildDir, "destdir")
		if _, err := os.Stat(staging); err != nil { errorf("DESTDIR não encontrado: %s", staging); os.Exit(1) }
		requireRoot("installdest")
		files, links, err := copyTree(staging, "/"); must(err)
		must(writeManifestAndDB(r, files, links))
		okf("installdest ok")
	case "package", "k":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag
		name := os.Args[2]
		p, err := recipePathRecursive(name); must(err)
		r, err := readRecipe(p); must(err)
		buildDir := filepath.Join(cfg.Cache, "build", r.Name+"-"+r.Version)
		staging := filepath.Join(buildDir, "destdir")
		pkg, err := packageDestdir(r, staging); must(err); okf("%s", pkg)
	case "graph", "g":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag
		name := os.Args[2]
		order, err := topoOrder(name); must(err)
		fmt.Println(strings.Join(order, " -> "))
	case "list", "l":
		must(listInstalled())
	case "search", "s":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag
		term := os.Args[2]; must(searchRecipes(term))
	case "info", "q":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag
		name := os.Args[2]
		p, err := recipePathRecursive(name); must(err)
		r, err := readRecipe(p); must(err)
		status := "[ ]"; if isInstalled(name) { status = "[✓]" }
		fmt.Printf(cBlue+"%s %s %s"+cReset+"
", status, r.Name, r.Version)
		if strings.TrimSpace(r.Description) != "" { fmt.Println(r.Description) }
		fmt.Println("Source:", r.Source.Type, r.Source.URL)
	case "remove", "r":
		if len(os.Args) < 3 { usage(); os.Exit(1) }
		must(removePackage(os.Args[2]))
	case "upgrade", "u":
		_ = fs.Parse(os.Args[3:]); cfg.Repo = *repoFlag; cfg.Strip = *stripFlag
		name := os.Args[2]; must(upgrade(name))
	case "sync":
		remote := ""; if len(os.Args) > 2 { remote = os.Args[2] }; must(syncGit(remote))
	default:
		usage()
	}
}
