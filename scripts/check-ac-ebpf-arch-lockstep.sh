#!/usr/bin/env bash
# Asserts the AC image build platform and AC launch-template instance families
# remain in lockstep for the pre-E5 eBPF gate (issue #2816).
#
# Why this lint exists:
#   - docker/Dockerfile.ac.aws compiles the eBPF .o files inside the AC image.
#   - build-and-push.yml must therefore build that image for the same platform
#     the prod AC launch template runs.
#   - The current supported state is intentionally single-arch: linux/amd64
#     image build, x86_64 AC EC2 families. A future arm64 or multi-arch AC path
#     must add a real on-arm64 BPF load test before this lint is relaxed.
#   - The EC2 family map below is an allow-list by design. New families should
#     fail here until their architecture is classified in the same PR.
#
# Testability: REPO_ROOT may be overridden via $AC_EBPF_ARCH_LOCKSTEP_ROOT so
# tests/scripts/check-ac-ebpf-arch-lockstep_test.sh can point the script at
# mutated fixture trees.

set -euo pipefail

REPO_ROOT="${AC_EBPF_ARCH_LOCKSTEP_ROOT:-$(git rev-parse --show-toplevel)}"
WF_SRC="${REPO_ROOT}/.github/workflows/build-and-push.yml"
TF_SRC="${REPO_ROOT}/terraform/modules/ac/main.tf"

for f in "$WF_SRC" "$TF_SRC"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: $f not found" >&2
    exit 1
  fi
done

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

extract_build_matrix_include_block() {
  awk '
    /^[[:space:]]{2}build:[[:space:]]*$/ {
      in_build_job = 1
      next
    }
    in_build_job && /^[[:space:]]{2}[[:alnum:]_-]+:[[:space:]]*$/ {
      exit
    }
    in_build_job && /^[[:space:]]*include:[[:space:]]*$/ {
      in_include = 1
      print
      next
    }
    in_include && /^[[:space:]]*steps:[[:space:]]*$/ {
      exit
    }
    in_include {
      print
    }
  ' "$WF_SRC"
}

build_matrix_block=$(extract_build_matrix_include_block)
[ -n "$build_matrix_block" ] || fail "could not find the build matrix include block in $WF_SRC"

extract_ac_matrix_block() {
  printf '%s\n' "$build_matrix_block" | awk '
    /^[[:space:]]*-[[:space:]]*image:[[:space:]]*ac[[:space:]]*$/ {
      in_ac = 1
      print
      next
    }
    in_ac && /^[[:space:]]*-[[:space:]]*image:[[:space:]]*/ {
      exit
    }
    in_ac {
      print
    }
  '
}

missing_platform_images=$(printf '%s\n' "$build_matrix_block" | awk '
  /^[[:space:]]*-[[:space:]]*image:[[:space:]]*[^[:space:]]+/ {
    if (in_entry && !has_platform) {
      print image
      bad = 1
    }
    in_entry = 1
    has_platform = 0
    image = $0
    sub(/^[[:space:]]*-[[:space:]]*image:[[:space:]]*/, "", image)
    sub(/[[:space:]]*$/, "", image)
    next
  }
  in_entry && /^[[:space:]]*platform:[[:space:]]*[^[:space:]]+/ {
    has_platform = 1
  }
  END {
    if (in_entry && !has_platform) {
      print image
      bad = 1
    }
    exit bad ? 1 : 0
  }
' || true)
if [ -n "$missing_platform_images" ]; then
  missing_platform_list=$(printf '%s\n' "$missing_platform_images" \
    | awk '{ out = out sep $0; sep = ", " } END { print out }')
  fail "every build matrix image in $WF_SRC must set 'platform:' because docker/build-push-action consumes matrix.platform. Missing platform for: ${missing_platform_list}"
fi

ac_block=$(extract_ac_matrix_block)
[ -n "$ac_block" ] || fail "could not find the build matrix entry '- image: ac' in $WF_SRC"

ac_platform=$(printf '%s\n' "$ac_block" \
  | awk '/^[[:space:]]*platform:[[:space:]]*[^[:space:]]+/ { print $2; exit }')
[ -n "$ac_platform" ] || fail "AC build matrix entry is missing 'platform: linux/amd64' in $WF_SRC"

if [[ "$ac_platform" == *,* ]]; then
  fail "AC build matrix platform is multi-platform (${ac_platform}); issue #2816 requires a real per-arch BPF load test before AC image builds become multi-arch"
fi

extract_build_push_action_block() {
  awk '
    /uses:[[:space:]]*docker\/build-push-action@/ {
      in_build = 1
      print
      next
    }
    in_build && /^[[:space:]]*-[[:space:]]/ {
      exit
    }
    in_build {
      print
    }
  ' "$WF_SRC"
}

build_action_count=$(grep -Ec 'uses:[[:space:]]*docker/build-push-action@' "$WF_SRC")
[ "$build_action_count" -eq 1 ] \
  || fail "expected exactly one docker/build-push-action step in $WF_SRC; found ${build_action_count}. Update scripts/check-ac-ebpf-arch-lockstep.sh before changing the build-step shape."

# Keep this scoped to the build action block so a stray matrix.platform mention
# elsewhere in the workflow cannot satisfy the load-bearing Buildx wiring.
build_action_block=$(extract_build_push_action_block)
printf '%s\n' "$build_action_block" \
  | grep -Eq '^[[:space:]]*platforms:[[:space:]]*\$\{\{[[:space:]]*matrix\.platform[[:space:]]*\}\}' \
  || fail "docker/build-push-action in $WF_SRC must pass 'platforms: \${{ matrix.platform }}' in its own with: block so the AC matrix platform is load-bearing"

extract_ac_autoscaling_group_block() {
  awk '
    /^[[:space:]]*resource[[:space:]]+"aws_autoscaling_group"[[:space:]]+"ac"[[:space:]]*\{/ {
      in_ac_asg = 1
      depth = 1
      print
      next
    }
    in_ac_asg {
      print
      open_line = $0
      close_line = $0
      opens = gsub(/\{/, "", open_line)
      closes = gsub(/\}/, "", close_line)
      depth += opens - closes
      if (depth <= 0) {
        exit
      }
    }
  ' "$TF_SRC"
}

ac_asg_block=$(extract_ac_autoscaling_group_block)
[ -n "$ac_asg_block" ] || fail "could not find resource \"aws_autoscaling_group\" \"ac\" in $TF_SRC"

# A MixedInstancesPolicy can override the launch-template instance_type without
# changing aws_launch_template.ac. Keep that future capacity shape fail-closed
# until this gate learns to classify every override instance_type too.
printf '%s\n' "$ac_asg_block" \
  | grep -Eq '^[[:space:]]*mixed_instances_policy[[:space:]]*\{' \
  && fail "AC ASG mixed_instances_policy overrides detected in $TF_SRC. This gate derives runtime architecture from aws_launch_template.ac instance_type only; update scripts/check-ac-ebpf-arch-lockstep.sh to classify all AC ASG override instance types before adding MixedInstancesPolicy. (issue #2816)"

extract_ac_launch_template_block() {
  # Lightweight Terraform extraction: this relies on the AC launch template
  # keeping instance_type near the resource header, before any heredoc or string
  # content that could contain unbalanced braces. If that shape changes, the
  # extraction-miss fixture should fail and this parser must move with it.
  # If AC capacity moves to ASG MixedInstancesPolicy overrides, update this gate
  # in that same PR; this script intentionally reads the launch-template
  # instance_type as today's source of truth.
  awk '
    /^[[:space:]]*resource[[:space:]]+"aws_launch_template"[[:space:]]+"ac"[[:space:]]*\{/ {
      in_ac_lt = 1
      depth = 1
      print
      next
    }
    in_ac_lt {
      print
      open_line = $0
      close_line = $0
      opens = gsub(/\{/, "", open_line)
      closes = gsub(/\}/, "", close_line)
      depth += opens - closes
      if (depth <= 0) {
        exit
      }
    }
  ' "$TF_SRC"
}

ac_launch_template_block=$(extract_ac_launch_template_block)
[ -n "$ac_launch_template_block" ] || fail "could not find resource \"aws_launch_template\" \"ac\" in $TF_SRC"

instance_line=$(printf '%s\n' "$ac_launch_template_block" \
  | grep -E '^[[:space:]]*instance_type[[:space:]]*=[[:space:]]*local\.is_prod[[:space:]]*\?[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*"[^"]+"' \
  | head -n1 || true)
[ -n "$instance_line" ] || fail "could not extract AC launch-template prod/non-prod instance_type ternary from resource \"aws_launch_template\" \"ac\" in $TF_SRC. If you refactored the instance_type expression into a local, variable, or override, update scripts/check-ac-ebpf-arch-lockstep.sh in the same change."

prod_instance=$(printf '%s\n' "$instance_line" | sed -E 's/^.*\?[[:space:]]*"([^"]+)".*$/\1/')
nonprod_instance=$(printf '%s\n' "$instance_line" | sed -E 's/^.*:[[:space:]]*"([^"]+)".*$/\1/')

[ -n "$prod_instance" ] || fail "could not extract prod AC instance type from $TF_SRC"
[ -n "$nonprod_instance" ] || fail "could not extract non-prod AC instance type from $TF_SRC"

platform_for_instance_type() {
  local instance_type="$1"
  local family="${instance_type%%.*}"

  case "$family" in
    # AWS Graviton / arm64 families. If AC moves here, issue #2816 requires a
    # real BPF object load on that architecture before the FilterMode flip.
    a1|c6g|c6gd|c6gn|c7g|c7gd|c7gn|c8g|g5g|im4gn|is4gen|m6g|m6gd|m7g|m7gd|m8g|r6g|r6gd|r7g|r7gd|r8g|t4g|x2gd)
      printf 'linux/arm64'
      ;;
    # x86_64 families currently supported by the AC image build path.
    c4|c5|c5a|c5ad|c5d|c5n|c6a|c6ad|c6i|c6id|c6in|c7a|c7i|c7i-flex|i3|i3en|i4i|i7i|m4|m5|m5a|m5ad|m5d|m5dn|m5n|m5zn|m6a|m6ad|m6i|m6id|m6idn|m6in|m7a|m7i|m7i-flex|r4|r5|r5a|r5ad|r5b|r5d|r5dn|r5n|r6a|r6ad|r6i|r6id|r6idn|r6in|r7a|r7i|r7iz|t2|t3|t3a)
      printf 'linux/amd64'
      ;;
    *)
      # This exits the function's command-substitution subshell; set -e on the
      # caller-side assignment makes the parent script abort too.
      fail "unknown AC instance family '${family}' from '${instance_type}'. Update scripts/check-ac-ebpf-arch-lockstep.sh with its architecture before changing AC capacity."
      ;;
  esac
}

prod_platform=$(platform_for_instance_type "$prod_instance")
nonprod_platform=$(platform_for_instance_type "$nonprod_instance")

mismatch=""
[ "$prod_platform" = "$ac_platform" ] \
  || mismatch+=$'\n'"  prod AC instance ${prod_instance} maps to ${prod_platform}, but AC image builds ${ac_platform}"
[ "$nonprod_platform" = "$ac_platform" ] \
  || mismatch+=$'\n'"  non-prod AC instance ${nonprod_instance} maps to ${nonprod_platform}, but AC image builds ${ac_platform}"

if [ "$ac_platform" != "linux/amd64" ]; then
  mismatch+=$'\n'"  AC image platform is ${ac_platform}; #2816 is amd64-only until a real non-amd64 BPF load test and per-arch build path land"
fi

if [ -n "$mismatch" ]; then
  cat <<EOF >&2
ERROR: AC eBPF build/runtime architecture drift.

       Source of truth - $WF_SRC:
         AC image platform = ${ac_platform}

       Source of truth - $TF_SRC:
         prod AC instance     = ${prod_instance} (${prod_platform})
         non-prod AC instance = ${nonprod_instance} (${nonprod_platform})

       Drift:${mismatch}

       Fix: keep the AC image build pinned to linux/amd64 while AC launch
       templates use x86_64 families. If the AC fleet moves to arm64 or the AC
       image becomes multi-arch, add the per-arch compile path plus a real BPF
       load test on that architecture before relaxing this gate. (issue #2816)
EOF
  exit 1
fi

echo "OK: AC eBPF arch lockstep holds (build=${ac_platform}; prod=${prod_instance}; non-prod=${nonprod_instance})"
