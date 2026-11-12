# 1. help (default target — must come first)
help:
	@echo "================================================"
	@echo "       $(OWNER)/$(PROJECT_NAME) by Startr.Cloud"
	@echo "================================================"
	@echo "This is the default make command."
	@echo "This command lists available make commands."
	@echo ""
	@echo "Usage example:"
	@echo "    make test"
	@echo ""
	@echo "Available make commands:"
	@echo ""
	@LC_ALL=C $(MAKE) -pRrq -f $(firstword $(MAKEFILE_LIST)) : 2>/dev/null | \
		awk -v RS= -F: '/(^|\n)# Files(\n|$$)/,/(^|\n)# Finished Make data base/ { \
		if ($$1 !~ "^[#.]") {print $$1}}' | \
		sort | \
		grep -E -v -e '^[^[:alnum:]]' -e '^$@$$'
	@echo ""

# 2. Dynamic variables (git-derived)
PROJECTPATH := $(shell git rev-parse --show-toplevel)
PROJECT     := $(shell echo $$(basename $(PROJECTPATH)) | tr '[:upper:]' '[:lower:]')
# Use symbolic-ref (clean failure on empty repos) → short SHA (detached HEAD) → develop fallback.
FULL_BRANCH := $(shell git symbolic-ref --short HEAD 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo "develop")
BRANCH      := $(shell echo $(FULL_BRANCH) | sed 's/.*\///' | tr '[:upper:]' '[:lower:]')
TAG         := $(shell git describe --always --tag 2>/dev/null || echo "v0.0.0")

# Owner and project name extracted from git remote URL
REMOTE_URL   := $(shell git config --get remote.origin.url 2>/dev/null || echo "unknown/unknown")
OWNER        := $(shell echo $(REMOTE_URL) | sed -E 's|.*[:/]([^/]+)/[^/]+(.git)?$$|\1|')
PROJECT_NAME := $(shell echo $(REMOTE_URL) | sed -E 's|.*[:/][^/]+/([^/]+)(.git)?$$|\1|' | sed 's/\.git$$//')

# Container name (unused here; kept for convention parity)
CONTAINER := $(PROJECT)-$(BRANCH)

# 3. Load environment overrides from .env if present
-include .env

# 4. Project-specific custom targets
UV := uv
# Engine locations from .env reach uv, pytest and the cleanroom CLI as environment.
export GHIDRA_INSTALL_DIR JAVA_HOME IDADIR CLEANROOM_ENGINE

install:
	$(UV) sync --locked --all-extras

test:
	$(UV) run pytest -m "not live" -q

test_live:
	$(UV) run pytest -m live -q

# make test_engines ENGINES=ghidra,jadx turns a missing-engine skip into a failure.
test_engines:
	CLEANROOM_REQUIRE_ENGINES=$(ENGINES) $(UV) run pytest -m "not live" -q

lint:
	$(UV) run ruff check . && $(UV) run ruff format --check .

fmt:
	$(UV) run ruff format . && $(UV) run ruff check --fix .

budget:
	$(UV) run pytest tests/test_budget.py tests/test_notice.py -q

build:
	rm -rf dist && $(UV) build

ci: lint budget test build

mcp:
	$(UV) run cleanroom mcp

doctor:
	$(UV) run cleanroom doctor

# make check_names NAMES="cleanroom cleanroom-re"; no NAMES checks the script's defaults.
check_names:
	$(UV) run python scripts/check_names.py $(NAMES)

show_version:
	@$(UV) version --short

# Sets the pyproject version from the release/* or hotfix/* branch name and
# commits it, so the tag git flow creates always equals v$(uv version --short).
# git-flow-next keeps the tag prefix per branch type: in .git/config after
# `git flow init`, or only in the committed .gitflow on a fresh clone.
bump_release_version:
	@case "$(FULL_BRANCH)" in \
		release/*) key=gitflow.branch.release.tagprefix ;; \
		hotfix/*) key=gitflow.branch.hotfix.tagprefix ;; \
		*) echo "Error: bump_release_version needs a release/* or hotfix/* branch (on $(FULL_BRANCH))"; exit 1 ;; \
	esac; \
	prefix=$$(git config --get "$$key" 2>/dev/null || git config --file .gitflow --get "$$key" 2>/dev/null); \
	test "$$prefix" = "v" || { \
		echo "Error: $$key must be 'v' (git flow init --shared -f -d -m master -e develop -t v)"; \
		exit 1; }
	@v=$$(echo "$(FULL_BRANCH)" | sed 's|^[^/]*/||'); \
	$(UV) version "$$v" && git add pyproject.toml uv.lock && \
	if git diff --cached --quiet; then echo "version already $$v, nothing to commit"; \
	else git commit -m "chore: bump version to $$v"; fi

# Security scanning + hook wiring.
# scan_tree is what the pre-push hook calls: gitleaks over the WHOLE working
# tree (--no-git), not just the staged diff, so anything a `--no-verify`
# commit let through is caught before it leaves the machine.
scan_tree:
	@gitleaks dir . --config .gitleaks.toml --redact --no-banner \
		&& echo "scan_tree: clean"

# scan_history audits the full git history, not just the current tree.
scan_history:
	@gitleaks git . --config .gitleaks.toml --redact --no-banner \
		&& echo "scan_history: clean"

scan: scan_tree scan_history

# Wire the hooks. Re-run after pulling hook changes to pick up new stages.
install_hooks:
	@$(UV) run pre-commit install --install-hooks
	@$(UV) run pre-commit install --hook-type pre-push
	@echo "hooks installed: pre-commit + pre-push"

# Interactive release: git-release from the sage-is/apps tap
release:
	@command -v git-release >/dev/null || { echo "Needs git-release: brew tap sage-is/apps && brew trust --tap sage-is/apps && brew install git-release"; exit 1; }
	@git-release

# 8. show_vars + verify (debug / one-shot self-check)
show_vars:
	@echo "=== Dynamic Variables ==="
	@echo "PROJECTPATH=$(PROJECTPATH)"
	@echo "PROJECT=$(PROJECT)"
	@echo "OWNER=$(OWNER)"
	@echo "PROJECT_NAME=$(PROJECT_NAME)"
	@echo "FULL_BRANCH=$(FULL_BRANCH)"
	@echo "BRANCH=$(BRANCH)"
	@echo "TAG=$(TAG)"
	@echo "CONTAINER=$(CONTAINER)"
	@echo "REMOTE_URL=$(REMOTE_URL)"
	@echo ""

# One-shot scaffold self-check. Bundles every read-only verification into a
# single make invocation so post-scaffold testing isn't N separate processes.
verify: show_vars require_gitflow_next
	@echo "=== Targets defined in this Makefile ==="
	@LC_ALL=C $(MAKE) -pRrq -f $(firstword $(MAKEFILE_LIST)) : 2>/dev/null | \
		awk -v RS= -F: '/(^|\n)# Files(\n|$$)/,/(^|\n)# Finished Make data base/ { \
		if ($$1 !~ "^[#.]") {print "  " $$1}}' | \
		sort -u | \
		grep -E -v -e '^  [^[:alnum:]]'
	@echo ""
	@echo "OK: Makefile scaffold verified."

# 9. Git-flow-next release/hotfix flow
require_gitflow_next:
	@if ! git flow version 2>/dev/null | grep -q 'git-flow-next'; then \
		echo "Error: git-flow-next required (Go rewrite). Install: brew install git-flow-next"; \
		exit 1; \
	fi

# CleanRoom change to the canonical recipes: before the first tag, the three
# bump targets start release/$(uv version --short) (0.1.0 the first time)
# instead of handing `git flow release start` an empty name.
minor_release: require_gitflow_next
	# Start a minor release with incremented minor version
	git flow release start $$(git tag --sort=-v:refname | sed 's/^v//' | head -n 1 | awk -F'.' '{print $$1"."$$2+1".0"}' | grep . || $(UV) version --short) && echo "or use 'make release_finish' to finish the release"

patch_release: require_gitflow_next
	# Start a patch release with incremented patch version
	git flow release start $$(git tag --sort=-v:refname | sed 's/^v//' | head -n 1 | awk -F'.' '{print $$1"."$$2"."$$3+1}' | grep . || $(UV) version --short) && echo "or use 'make release_finish' to finish the release"

major_release: require_gitflow_next
	# Start a major release with incremented major version
	git flow release start $$(git tag --sort=-v:refname | sed 's/^v//' | head -n 1 | awk -F'.' '{print $$1+1".0.0"}' | grep . || $(UV) version --short) && echo "or use 'make release_finish' to finish the release"

# git-release's "custom" choice: make custom_release VER=1.2.3
custom_release: require_gitflow_next
	@test -n "$(VER)" || { echo "Error: make custom_release VER=X.Y.Z"; exit 1; }
	git flow release start $(VER) && echo "or use 'make release_finish' to finish the release"

hotfix: require_gitflow_next
	# Start a hotfix with incremented n.n.n.n version (incrementing the fourth number)
	git flow hotfix start $$(git tag --sort=-v:refname | sed 's/^v//' | head -n 1 | awk -F'.' '{print $$1"."$$2"."$$3"."$$4+1}') && echo "or use 'make hotfix_finish' to finish the hotfix"

# CleanRoom change to the canonical recipes: release_finish and hotfix_finish
# depend on bump_release_version, so pyproject.toml always matches the tag.
release_finish: require_gitflow_next bump_release_version
	git flow release finish && git push origin develop && git push origin master && git push --tags && git checkout develop

hotfix_finish: require_gitflow_next bump_release_version
	git flow hotfix finish && git push origin develop && git push origin master && git push --tags && git checkout master

# 10. things_clean
things_clean:
	git clean --exclude='!.env*' -Xdf

# 11. .PHONY declarations
.PHONY: help show_vars verify require_gitflow_next \
	minor_release patch_release major_release custom_release hotfix \
	release_finish hotfix_finish things_clean \
	install test test_live test_engines lint fmt budget build ci mcp doctor \
	check_names show_version bump_release_version \
	scan_tree scan_history scan install_hooks release

## >>> startr worktree block v1 (startr.sh/Makefile, 2026-11-12) >>>
## One checkout per repo. A worktree is for one parallel task, and it goes
## the day its branch lands; a landed branch goes too. wt_check fails while
## either lingers, so the rule is a gate, not a memory.
## To update a repo, replace everything between the two marker lines.
## Guide: https://startr.sh/docs/makefile-worktrees/
##   make wt NAME=quick-note       feature/quick-note from WT_BASE, in ../<repo>-wt/quick-note
##   make wt NAME=fix/typo         a name with a slash is the branch; the folder is fix-typo
##   make wt_list                  each worktree and spare branch: ahead/behind, changes, age
##   make wt_done NAME=quick-note  clean and landed only: removes the worktree and its branch
##   make wt_tidy                  wt_done for every clean, landed worktree and branch
##   make wt_check                 fails on a landed worktree or branch, or one over WT_DAYS
## "Landed" means merging the branch into WT_BASE changes nothing: merged,
## squashed or rebased in. The remote branch is never touched.
WT_BASE ?= $(shell for b in develop main master; do git rev-parse -q --verify "refs/heads/$$b" >/dev/null && { echo $$b; break; }; done)
WT_MAX ?= 3
WT_DAYS ?= 3
WT_KEEP ?= develop main master gh-pages

.PHONY: wt wt_list wt_done wt_tidy wt_check

## Shell functions the five targets share. Every worktree but the main
## checkout prints as "path<TAB>branch" ("-" when detached).
define wt_sh
tab=$$(printf '\t'); now=$$(date +%s); base="$(WT_BASE)"; \
main=$$(cd "$$(git rev-parse --path-format=absolute --git-common-dir)/.." && pwd); \
root="$$main-wt"; \
git worktree prune; \
worktrees() { git worktree list --porcelain | awk '/^worktree /{n++; p=substr($$0,10)} n>1 && /^branch /{print p "\t" substr($$0,19)} n>1 && /^detached/{print p "\t-"}'; }; \
spare_branches() { held=$$(git worktree list --porcelain | sed -n 's|^branch refs/heads/||p'); \
	git for-each-ref --format='%(refname:short)' refs/heads | while read -r b; do \
	case " $(WT_KEEP) $$base " in *" $$b "*) continue;; esac; \
	printf '%s\n' "$$held" | grep -qxF "$$b" || echo "$$b"; done; }; \
contained() { git merge-base --is-ancestor "$$1" "$$base" && return 0; \
	t=$$(git merge-tree --write-tree "$$base" "$$1" 2>/dev/null) && [ "$$t" = "$$(git rev-parse "$$base^{tree}")" ]; }; \
worked() { [ "$$(git reflog show "refs/heads/$$1" 2>/dev/null | wc -l | tr -d ' ')" -gt 1 ]; }; \
age() { c=$$(git reflog show --date=unix --format=%gd "refs/heads/$$1" 2>/dev/null | tail -1 | sed -n 's/.*@{\([0-9]*\)}$$/\1/p'); \
	[ -n "$$c" ] && echo $$(( (now - c) / 86400 )) || echo 0; }; \
changes() { git -C "$$1" status --porcelain | wc -l | tr -d ' '; }; \
remove_one() { if [ -n "$$1" ]; then git worktree remove "$$1" || return 1; echo "Removed $$1"; fi; \
	if [ "$$2" != "-" ]; then git branch -D "$$2" >/dev/null && echo "Deleted $$2 (its work is in $$base)"; \
	git rev-parse -q --verify "refs/remotes/origin/$$2" >/dev/null && echo "  origin still has it: git push origin --delete $$2"; fi; \
	rmdir "$$root" 2>/dev/null; true; }
endef

## The bodies of wt_list and wt_check, shared with wt and wt_tidy. They are
## defines, not recursive $(MAKE) calls, so `make -n wt` runs nothing.
define wt_list_sh
echo "base: $${base:-none}"; \
worktrees | while IFS="$$tab" read -r p b; do \
	n=$$(changes "$$p"); line="$$p  $$b  $$n changed"; \
	if [ "$$b" != "-" ] && [ -n "$$base" ]; then \
		line="$$line  +$$(git rev-list --count "$$base..$$b")/-$$(git rev-list --count "$$b..$$base")  $$(age "$$b")d"; \
		[ "$$n" = 0 ] && worked "$$b" && contained "$$b" && line="$$line  LANDED: make wt_done"; \
	fi; echo "$$line"; done; \
[ -n "$$base" ] && spare_branches | while read -r b; do \
	line="branch $$b  +$$(git rev-list --count "$$base..$$b")/-$$(git rev-list --count "$$b..$$base")  $$(age "$$b")d"; \
	contained "$$b" && line="$$line  LANDED: make wt_done NAME=$$b"; echo "$$line"; done; true
endef

define wt_check_sh
[ -n "$$base" ] || { echo "wt_check: no develop, main or master branch here; skipped"; exit 0; }; \
bad=$$( worktrees | while IFS="$$tab" read -r p b; do \
	[ "$$b" = "-" ] && continue; \
	[ "$$(changes "$$p")" = 0 ] && worked "$$b" && contained "$$b" && { echo "  landed worktree: $$p ($$b)"; continue; }; \
	[ "$$(age "$$b")" -le $(WT_DAYS) ] || echo "  $$(age "$$b") days old: $$p ($$b); land it or make wt_done"; done; \
	spare_branches | while read -r b; do contained "$$b" && echo "  landed branch: $$b"; done ); \
[ -z "$$bad" ] || { echo "wt_check failed (WT_DAYS=$(WT_DAYS)):"; echo "$$bad"; echo "make wt_tidy clears what landed; land or drop the rest."; exit 1; }
endef

wt:
	@[ "$(origin NAME)" = "command line" ] || { echo "Usage: make wt NAME=quick-note"; exit 1; }; \
	$(wt_sh); [ -n "$$base" ] || { echo "No develop, main or master branch: set WT_BASE"; exit 1; }; \
	case "$(NAME)" in */*) b="$(NAME)";; *) b="feature/$(NAME)";; esac; \
	dir="$$root/$$(echo "$(NAME)" | tr / -)"; \
	open=$$(worktrees | wc -l | tr -d ' '); \
	[ "$$open" -lt $(WT_MAX) ] || { echo "$$open worktrees open, and WT_MAX is $(WT_MAX). Land one, then make wt_done."; worktrees; exit 1; }; \
	( $(wt_check_sh) ) || { echo "Clear those before a new worktree."; exit 1; }; \
	! git rev-parse -q --verify "refs/heads/$$b" >/dev/null || { echo "$$b already exists"; exit 1; }; \
	git worktree add -q -b "$$b" "$$dir" "$$base" && \
	echo "Ready: cd $$dir ($$b from $$base). When it lands: make wt_done NAME=$(NAME)"

wt_list:
	@$(wt_sh); $(wt_list_sh)

wt_done:
	@[ "$(origin NAME)" = "command line" ] || { echo "Usage: make wt_done NAME=quick-note"; exit 1; }; \
	$(wt_sh); [ -n "$$base" ] || { echo "No develop, main or master branch: set WT_BASE"; exit 1; }; \
	case "$(NAME)" in */*) want="$(NAME)";; *) want="feature/$(NAME)";; esac; \
	dir="$$root/$$(echo "$(NAME)" | tr / -)"; \
	hit=$$(worktrees | awk -F"$$tab" -v d="$$dir" -v b="$$want" '$$1==d || $$2==b {print; exit}'); \
	if [ -n "$$hit" ]; then p=$${hit%%"$$tab"*}; b=$${hit#*"$$tab"}; \
	elif git rev-parse -q --verify "refs/heads/$$want" >/dev/null; then p=; b="$$want"; \
	else echo "No worktree at $$dir and no branch $$want"; exit 1; fi; \
	if [ -n "$$p" ]; then \
		case "$$(pwd -P)/" in "$$(cd "$$p" && pwd -P)/"*) echo "Run it from $$main, not from inside the worktree"; exit 1;; esac; \
		n=$$(changes "$$p"); [ "$$n" = 0 ] || { echo "$$p has $$n uncommitted changes:"; git -C "$$p" status --short; exit 1; }; \
	fi; \
	[ "$$b" = "-" ] || contained "$$b" || { echo "$$b is not in $$base yet: $$(git rev-list --count "$$base..$$b") commits to land"; exit 1; }; \
	remove_one "$$p" "$$b"

wt_tidy:
	@$(wt_sh); [ -n "$$base" ] || { echo "No develop, main or master branch: set WT_BASE"; exit 1; }; \
	worktrees | while IFS="$$tab" read -r p b; do \
		[ "$$b" != "-" ] && [ "$$(changes "$$p")" = 0 ] && worked "$$b" && contained "$$b" && remove_one "$$p" "$$b"; done; \
	spare_branches | while read -r b; do contained "$$b" && remove_one "" "$$b"; done; \
	$(wt_list_sh)

wt_check:
	@$(wt_sh); $(wt_check_sh)
## <<< startr worktree block v1 <<<
