
END_MARKER="--->END<---"

# Check wether the signature on a file can be verified with the given key
function has_valid_ima_signature()
{
	local fn="$1"
	local imakey="$2"

	if [ "${imakey}" = "ignore" ]; then
		return 0
	elif [ "${imakey}" = "available" ]; then
		if [ -n "$(getfattr -m ^security.ima -e hex --dump "${fn}" 2>/dev/null)" ]; then
			return 0
		fi
		return 1
	else
		evmctl ima_verify --key "${imakey}" "${fn}" &>/dev/null
		return $?
	fi
}

function get_library_dirs()
{
	local semfile="$1"

	# Libraries are only in certain directories and should be quick to find
	# find / -type f -name '*.so.*' -executable -print
	# relevant dirs: sudo semanage fcontext --list | grep -E "(:lib_t):"
	grep -E ":lib_t:" "${semfile}" \
		| sed -n 's|^\(/[^/]*/\).*|\1|p' \
		| sort \
		| uniq \
		| grep -vE "/(dev|bin|lib)/"
}

function get_executable_dirs()
{
	local semfile="$1"

	# Should walk whole filesystem with following command:
	# find / -type f -name -executable -print
	# Also libraries could be executables (?)
	# relevant dirs: sudo semanage fcontext --list | grep -E "(exec_t|:bin_t):"
	grep -E "(_exec_t|:bin_t):" "${semfile}" \
		| sed -n 's|^\(/[^/]*/\).*|\1|p' \
		| sort \
		| uniq \
		| grep -vE "/(dev|bin|lib)/"
}

function get_text_file_dirs()
{
	local semfile="$1"

	# Should walk whole filesystem since any file can be a text file
	sed -n 's|^\(/[^/(=\[]*/\).*|\1|p' < "${semfile}" \
		| sort \
		| uniq \
		| grep -vE "/(dev|bin|lib|proc|sys)/"
}

# Gather all SELinux labels in this directory and its sub-directories
# using the find tool
function ima_selinux_gather_labels_by_dir()
{
	local dir="$1"
	local opts="$2"

	local fn

	set -f

	(find "${dir}" ${opts} -type f;
		echo "${END_MARKER}" )| while read -r fn; do
		if [ "${fn}" = "${END_MARKER}" ]; then
			wait
			break
		fi
		getfattr -m ^security.selinux --dump "${fn}" 2>/dev/null | \
			sed -n 's/security.selinux="\([^"]*\)"/\1/p' &
	done \
		| sort \
		| uniq

	set +f
}

function check_file_signature()
{
	local fn="$1"
	local report_failed="$2"
	local keys="$3"
	local signkey="$4"
	local verbose="$5"

	local key valid keys_arr OIFS="$IFS"

	IFS="," keys_arr=(${keys})
	IFS="${OIFS}"

	valid=0
	for key in ${keys_arr[*]}; do
		if has_valid_ima_signature "${fn}" "${key}"; then
			valid=1
			break
		fi
	done

	if [ "${valid}" -eq 1 ]; then
		if [ "${report_failed}" -eq 0 ]; then
			getfattr -m ^security.selinux --dump "${fn}" 2>/dev/null | \
				sed -n 's/security.selinux="\([^"]*\)"/\1/p' &
		fi
		#[ "${verbose}" -ne 0 ] && echo "GOOD: ${fn}" >&2
	else
		if [ -n "${signkey}" ]; then
			local errmsg

			if ! errmsg=$(evmctl ima_sign --key "${signkey}" "${fn}" 2>&1); then
				echo "Signing with key ${signkey} failed." >&2
				echo "${errmsg}" >&2
				exit 1
			fi
		else
			if [ "${report_failed}" -ne 0 ]; then
				getfattr -m ^security.selinux --dump "${fn}" 2>/dev/null | \
					sed -n 's/security.selinux="\([^"]*\)"/\1/p' &
			fi
			if [ "${verbose}" -ne 0 ]; then
				echo " BAD: ${fn}" >&2
				ls -lZ "${fn}" >&2
			fi
		fi
	fi
}

# Check the signatures of all files in a directory; report the SELinux labels
# of either files passing or failing signature checks
function ima_selinux_check_signatures_by_dir()
{
	local dir="$1"
	local opts="$2"
	local report_failed="$3"
	local keys="$4"
	local signkey="$5"
	local verbose="$6"

	local fn

	set -f

	if [ ! -e "${dir}" ]; then
		return
	fi

	(find "${dir}" ${opts} -type f;
		echo "${END_MARKER}" )| while read -r fn; do
		if [ "${fn}" = "${END_MARKER}" ]; then
			wait
			break
		fi

		check_file_signature "${fn}" "${report_failed}" "${keys}" "${signkey}" "${verbose}" &
	done \
		| sort \
		| uniq

	set +f
}

function ima_policy_generate_header()
{
	local appraise_rules="$1"
	local measure_rules="$2"

	local magic fs

	for fs_magic in \
		0x9fa0,proc \
		0x62656572,sysfs \
		0x64626720,debugfs \
		0x1021994,tmpfs \
		0x858458f6,ramfs \
		0x1cd1,devpts \
		0x42494e4d,binfmtfs \
		0x73636673,securityfs \
		0xf97cff8c,selinux \
		0x43415d53,smack \
		0x27e0eb,cgroup \
		0x63677270,cgroup2 \
		0x6e736673,nsfs \
		0xde5e81e4,efivarfs; do

		magic=$(echo "${fs_magic}" | cut -d"," -f1)
		fs=$(echo "${fs_magic}" | cut -d"," -f2)

		[ "${appraise_rules}" -ne 0 ] || [ "${measure_rules}" -ne 0 ] &&
			echo "# ${fs}"
		[ "${appraise_rules}" -ne 0 ] &&
			echo "dont_appraise fsmagic=${magic}"
		[ "${measure_rules}" -ne 0 ] &&
			echo "dont_measure fsmagic=${magic}"
	done
}
