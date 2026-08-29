#!/usr/bin/env bash
#
# release.sh — liuzx-sdf-jce 一键发布脚本
#
# 流程：打包 → 发布到 Maven Central → 打 Git tag → 升级到下一个 -SNAPSHOT 版本
#
# 用法：
#   ./release.sh                          # 用 pom.xml 当前版本发布（须为正式版，如 1.1.3）
#   ./release.sh --version 1.2.0          # 先改版本为 1.2.0 再发布
#   ./release.sh --with-tests             # 打包与发布时运行单元测试（依赖真实 SDF 硬件）
#   ./release.sh --update-docs            # 同步更新 README.md / index.html 版本号与产物名
#   ./release.sh --dry-run                # 演练：只打印将执行的命令，不做任何修改
#   ./release.sh --yes                    # 跳过确认提示（CI 用）
#   ./release.sh --no-tag                 # 不创建 Git tag
#   ./release.sh --no-commit              # 不提交 Git 变更（也会跳过打 tag）
#   ./release.sh --push                   # 发布成功后推送提交与 tag 到 origin
#   ./release.sh -h | --help              # 显示帮助
#
# 前置条件（详见 RELEASE.md）：
#   1. ~/.m2/settings.xml 已配置 <server id="central">（Central Portal User Token），
#      以及名为 gpg-signing 的 profile（含 gpg.keyname / gpg.passphrase）
#   2. org.liuzx 命名空间已在 https://central.sonatype.com 完成域名验证
#   3. pom.xml 当前版本为正式版（Central 拒收 SNAPSHOT）
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POM="$PROJECT_DIR/pom.xml"
MVN="${MVN:-mvn}"
REMOTE="${REMOTE:-origin}"
TODAY="$(date +%Y-%m-%d)"

# BSD sed (macOS) 与 GNU sed 的 -i 参数不同
if sed --version >/dev/null 2>&1; then
  SED_INPLACE=(-i)
else
  SED_INPLACE=(-i "")
fi

# 颜色（非 TTY 时关闭）
if [[ -t 1 ]]; then
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_OFF=""
fi

info() { printf "%s[INFO]%s  %s\n"  "$C_GREEN" "$C_OFF" "$*"; }
warn() { printf "%s[WARN]%s  %s\n"  "$C_YELLOW" "$C_OFF" "$*"; }
die()  { printf "%s[ERROR]%s %s\n"  "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

# 执行命令（--dry-run 时只打印）
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf "%s[DRY-RUN]%s %s\n" "$C_YELLOW" "$C_OFF" "$*"
  else
    printf "%s\$%s %s\n" "$C_BOLD" "$C_OFF" "$*"
    "$@"
  fi
}

# 执行带重定向/管道的 shell 命令（--dry-run 时只打印）
run_sh() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf "%s[DRY-RUN]%s %s\n" "$C_YELLOW" "$C_OFF" "$1"
  else
    printf "%s\$%s %s\n" "$C_BOLD" "$C_OFF" "$1"
    eval "$1"
  fi
}

# 确认提示（--yes / --dry-run 时直接通过）
confirm() {
  [[ "$ASSUME_YES" == "1" || "$DRY_RUN" == "1" ]] && return 0
  local ans
  printf "%s[?]%s %s [y/N] " "$C_YELLOW" "$C_OFF" "$1"
  read -r ans || true
  [[ "$ans" == "y" || "$ans" == "Y" ]] || die "已取消"
}

# 参数默认值
VERSION=""; DRY_RUN=0; ASSUME_YES=0; WITH_TESTS=0; UPDATE_DOCS=0
SKIP_BUILD=0; DO_TAG=1; DO_COMMIT=1; DO_PUSH=0

usage() { sed -n '3,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)     VERSION="${2:?--version 需要一个参数}"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --yes)         ASSUME_YES=1; shift ;;
    --with-tests)  WITH_TESTS=1; shift ;;
    --update-docs) UPDATE_DOCS=1; shift ;;
    --skip-build)  SKIP_BUILD=1; shift ;;
    --no-tag)      DO_TAG=0; shift ;;
    --no-commit)   DO_COMMIT=0; shift ;;
    --push)        DO_PUSH=1; shift ;;
    -h|--help)     usage ;;
    *) die "未知参数: $1（用 --help 查看用法）" ;;
  esac
done

# ---------- 工具函数 ----------
version_from_pom() { sed -n 's/.*<version>\([^<]*\)<\/version>.*/\1/p' "$POM" | head -1; }
validate_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "版本号不合法: $1（应为 x.y.z，如 1.1.3）"; }

# 1.1.3 -> 1.1.4-SNAPSHOT
next_snapshot() {
  local v="$1" major minor patch
  IFS='.' read -r major minor patch <<< "$v"
  printf '%s.%s.%s-SNAPSHOT\n' "$major" "$minor" "$((patch + 1))"
}

# README「当前版本」行的版本号
doc_version() { sed -n 's/.*当前版本: \([0-9.]*\).*/\1/p' "$PROJECT_DIR/README.md" | head -1; }

git_has_changes() { [[ -n "$(git status --porcelain 2>/dev/null)" ]]; }

check_preflight() {
  command -v "$MVN" >/dev/null 2>&1 || die "未找到 mvn（可设置 MVN=/path/to/mvn 指定）"
  command -v git >/dev/null 2>&1 || die "未找到 git"
  command -v gpg >/dev/null 2>&1 || warn "未找到 gpg，GPG 签名步骤可能失败"
  [[ -f "$POM" ]] || die "未找到 $POM"

  local settings="${HOME}/.m2/settings.xml"
  if [[ -f "$settings" && $(grep -c '<id>central</id>' "$settings" 2>/dev/null || true) -gt 0 ]]; then
    info "已找到 ~/.m2/settings.xml 中的 <server id=\"central\"> 配置"
  else
    warn "~/.m2/settings.xml 缺少 <server id=\"central\">（Central Portal User Token），发布将 401"
  fi

  if git rev-parse "v$RELEASE" >/dev/null 2>&1; then
    die "tag v$RELEASE 已存在，请检查是否重复发布"
  fi
}

# ---------- 主流程 ----------
main() {
  cd "$PROJECT_DIR"

  # 0. 确定发布版本
  CURRENT="$(version_from_pom)"
  [[ -n "$CURRENT" ]] || die "无法从 pom.xml 读取当前版本"

  if [[ -n "$VERSION" ]]; then
    validate_version "$VERSION"
    RELEASE="$VERSION"
  else
    if [[ "$CURRENT" == *-SNAPSHOT ]]; then
      die "pom.xml 当前版本是 ${CURRENT}（SNAPSHOT），Central 拒收。请用 --version <x.y.z> 指定发布版本"
    fi
    RELEASE="$CURRENT"
  fi
  validate_version "$RELEASE"

  NEXT="$(next_snapshot "$RELEASE")"
  NEED_VERSION_SET=0
  [[ -n "$VERSION" && "$VERSION" != "$CURRENT" ]] && NEED_VERSION_SET=1

  check_preflight

  # 1. 打印发布计划并确认
  echo
  info "=============== 发布计划 ==============="
  info "项目        : liuzx-sdf-jce"
  info "当前版本    : $CURRENT"
  info "发布版本    : $RELEASE"
  info "发布后版本  : $NEXT"
  info "打包        : $([[ "$SKIP_BUILD" == 1 ]] && echo "跳过(--skip-build)" || echo "mvn clean $([[ "$WITH_TESTS" == 1 ]] && echo verify || echo package)")"
  info "发布        : mvn clean deploy -Prelease,gpg-signing -DskipTests=$([[ "$WITH_TESTS" == 1 ]] && echo false || echo true)"
  [[ "$DO_TAG" == 1 ]]     && info "Git tag     : v$RELEASE"
  [[ "$DO_COMMIT" == 1 ]]  && info "提交        : chore(release): 发布 $RELEASE 到 Maven Central / 回到 $NEXT"
  [[ "$DO_PUSH" == 1 ]]    && info "推送        : git push $REMOTE HEAD --tags"
  if [[ "$DO_COMMIT" == 1 ]] && git_has_changes; then
    warn "工作区有未提交变更，将一并纳入发布提交（如不想提交，请先自行处理）"
  fi
  info "========================================="
  echo

  confirm "确认开始发布 ${RELEASE}？"

  # 2. 设置发布版本（如需要）
  if [[ "$NEED_VERSION_SET" == 1 ]]; then
    info "把 pom.xml 版本 $CURRENT -> $RELEASE"
    run sed "${SED_INPLACE[@]}" "s|<version>${CURRENT}</version>|<version>${RELEASE}</version>|" "$POM"
    CURRENT="$RELEASE"
  fi

  # 3. 打包（提前暴露编译/测试问题）
  if [[ "$SKIP_BUILD" == 1 ]]; then
    warn "跳过打包步骤（--skip-build）"
  elif [[ "$WITH_TESTS" == 1 ]]; then
    info "打包并运行单元测试（需真实 SDF 硬件）..."
    run "$MVN" clean verify -DskipTests=false
  else
    info "打包（跳过硬件测试，pom 默认 skipTests=true）..."
    run "$MVN" clean package
  fi

  # 4. 发布到 Maven Central
  info "发布到 Maven Central（release: 发布产物；gpg-signing: 签名凭据）..."
  if [[ "$WITH_TESTS" == 1 ]]; then
    run "$MVN" clean deploy -Prelease,gpg-signing -DskipTests=false
  else
    run "$MVN" clean deploy -Prelease,gpg-signing -DskipTests=true
  fi
  info "Central 校验通过并已提交发布（autoPublish=true，Portal 上异步完成最终发布）"

  # 5. 更新文档版本号（可选）
  if [[ "$UPDATE_DOCS" == 1 ]]; then
    local dver
    dver="$(doc_version)"
    if [[ -n "$dver" && "$dver" != "$RELEASE" ]]; then
      info "更新 README.md / index.html: $dver -> $RELEASE"
      run sed "${SED_INPLACE[@]}" "s|当前版本: ${dver}\*\*（[0-9-]*）|当前版本: ${RELEASE}**（${TODAY}）|" "$PROJECT_DIR/README.md"
      run sed "${SED_INPLACE[@]}" "s|liuzx-sdf-jce-${dver}\.jar|liuzx-sdf-jce-${RELEASE}.jar|g" "$PROJECT_DIR/README.md"
      run sed "${SED_INPLACE[@]}" "s|<version>${dver}</version>|<version>${RELEASE}</version>|" "$PROJECT_DIR/README.md"
      run sed "${SED_INPLACE[@]}" "s|>v${dver} ·|>v${RELEASE} ·|" "$PROJECT_DIR/index.html"
      run sed "${SED_INPLACE[@]}" "s|liuzx-sdf-jce-${dver}\.jar|liuzx-sdf-jce-${RELEASE}.jar|g" "$PROJECT_DIR/index.html"
      # 在「当前版本」行后插入新的 changelog 占位条目（内容需人工补充）
      run_sh "awk -v nv=\"$RELEASE\" -v td=\"$TODAY\" '/^\\*\\*当前版本:/ { print; print \"\"; printf \"### %s (%s)\\n\\n- （发布脚本自动插入，请补充本次变更说明）\\n\", nv, td; next } { print }' \"$PROJECT_DIR/README.md\" > \"$PROJECT_DIR/README.md.tmp\" && mv \"$PROJECT_DIR/README.md.tmp\" \"$PROJECT_DIR/README.md\""
    else
      warn "README 未找到旧版本号或已是新版本，跳过文档更新"
    fi
  fi

  # 6. Git 提交 + 打 tag（tag 指向「发布版本」提交）
  if [[ "$DO_COMMIT" == 1 ]]; then
    run git add -A
    run git commit -m "chore(release): 发布 $RELEASE 到 Maven Central"
    if [[ "$DO_TAG" == 1 ]]; then
      run git tag "v$RELEASE"
      info "已打 tag: v$RELEASE"
    else
      warn "跳过打 tag（--no-tag）"
    fi
  elif [[ "$DO_TAG" == 1 ]]; then
    warn "--no-commit 模式下跳过打 tag（tag 需指向发布提交）"
  fi

  # 7. 升级为下一个 -SNAPSHOT
  info "升级版本 $RELEASE -> $NEXT"
  run sed "${SED_INPLACE[@]}" "s|<version>${RELEASE}</version>|<version>${NEXT}</version>|" "$POM"
  if [[ "$DO_COMMIT" == 1 ]]; then
    run git add "$POM"
    run git commit -m "chore(release): 回到 $NEXT"
  fi

  # 8. 推送（可选）
  if [[ "$DO_PUSH" == 1 ]]; then
    info "推送提交与 tag 到 $REMOTE ..."
    run git push "$REMOTE" HEAD
    [[ "$DO_TAG" == 1 && "$DO_COMMIT" == 1 ]] && run git push "$REMOTE" --tags
  fi

  # 9. 完成
  echo
  info "=============== 发布完成 ==============="
  info "发布版本    : ${RELEASE}（构建产物 target/liuzx-sdf-jce-${RELEASE}.jar）"
  info "Git tag     : v$RELEASE"
  info "当前版本    : $NEXT"
  info "下一步      : 到 https://central.sonatype.com → Publish 页确认最终发布状态；"
  info "             autoPublish 通过后，几分钟内可见 https://repo1.maven.org/maven2/org/liuzx/liuzx-sdf-jce/"
  info "========================================"
}

main "$@"
