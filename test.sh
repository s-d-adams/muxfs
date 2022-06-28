#!/bin/sh

set -e

if [ ! -e 'test.conf' ]
then	echo 'Please read test.conf.dist.'
	exit 1
fi
. ./test.conf

chk_alg='invalid'

testsuite_init() {
	if pgrep -q mount_muxfs
	then	echo 'muxfs already running'
		exit 1
	fi
	rm -r "${test_tmp}" "${dev_a}" "${dev_b}" "${mp}" \
	    >/dev/null 2>&1 || true
	mkdir "${mp}"
}
testsuite_final() {
	rmdir "${mp}"
}
pre_test() {
	mkdir "${test_tmp}" "${dev_a}" "${dev_b}"
	./newfs_muxfs -a "${chk_alg}" "-d${dev_a}" "-d${dev_b}"
	./mount_muxfs "${dev_a}" "${dev_b}" "${mp}"
}
post_test() {
	umount "${mp}"
	rm -r "${test_tmp}" "${dev_a}" "${dev_b}"
}
run_tests() {
	for t in $1
	do	echo "${t}"
		pre_test
		sleep 0.01
		${t}
		post_test
	done
}

test_mknod() {
	touch "${mp}/r"
	cat "${dev_a}/r" >/dev/null
	cat "${dev_b}/r" >/dev/null
}
test_mkdir() {
	mkdir "${mp}/d"
	ls "${dev_a}/d" >/dev/null
	ls "${dev_b}/d" >/dev/null
}
test_symlink() {
	ln -s 'foo' "${mp}/l"
	readlink "${dev_a}/l" >/dev/null
	readlink "${dev_b}/l" >/dev/null
}
test_getattr() {
	test_mknod
	test_mkdir
	test_symlink
	ls -l "${mp}" >/dev/null
}
test_write() {
	test_mknod
	echo 'foo' >"${mp}/r"
}
test_truncate() {
	test_write
	>"${mp}/r"
}
test_chmod() {
	test_mknod
	chmod 0700 "${mp}/r"
}
test_chown() {
	test_mknod
	chown "${unpriv_user}" "${mp}/r"
}
test_rename() {
	test_mknod
	mv "${mp}/r" "${mp}/r2"
	cat "${dev_a}/r2" >/dev/null
	cat "${dev_b}/r2" >/dev/null
}
test_read() {
	test_write
	cat "${mp}/r" >/dev/null
}
test_readlink() {
	test_symlink
	readlink "${mp}/l" >/dev/null
}
test_readdir() {
	test_getattr
}
test_unlink_reg() {
	test_mknod
	rm "${mp}/r"
}
test_unlink_lnk() {
	test_symlink
	rm "${mp}/l"
}
test_rmdir() {
	test_mkdir
	rmdir "${mp}/d"
}
test_lfile_write() {
	dd status=none if=/dev/urandom "of=${test_tmp}/r" bs=1k count=7
	cp "${test_tmp}/r" "${mp}/r"
	cmp -s "${test_tmp}/r" "${dev_a}/r"
	cmp -s "${test_tmp}/r" "${dev_b}/r"
}
test_lfile_read() {
	test_lfile_write
	cmp -s "${test_tmp}/r" "${mp}/r"
}
test_lfile_truncate_large_to_small() {
	test_lfile_write
	echo 'foo' >"${mp}/r"
	test "$(<"${dev_a}/r")" == 'foo'
	test "$(<"${dev_b}/r")" == 'foo'
}
test_lfile_extend_large_to_larger() {
	test_lfile_write
	dd status=none if=/dev/urandom "of=${test_tmp}/r2" bs=1k count=4
	cat "${test_tmp}/r2" >>"${test_tmp}/r"
	cat "${test_tmp}/r2" >>"${mp}/r"
	cmp -s "${test_tmp}/r" "${dev_a}/r"
	cmp -s "${test_tmp}/r" "${dev_b}/r"
}

basic_tests='test_mknod test_mkdir test_symlink test_getattr test_write '\
'test_truncate test_chmod test_chown test_rename test_read '\
'test_readlink test_readdir test_unlink_reg test_unlink_lnk '\
'test_rmdir test_lfile_write test_lfile_read '\
'test_lfile_truncate_large_to_small test_lfile_extend_large_to_larger'

test_basics() {
	run_tests "${basic_tests}"
}

test_resiliance_reg() {
	test_write
	echo 'bad' >"${dev_a}/r"
	test "$(<"${mp}/r")" == 'foo'
}
test_resiliance_lnk() {
	test_symlink
	ln -sf 'bar' "${dev_a}/l"
	test "$(readlink "${mp}/l")" == 'foo'
}
test_resiliance_dir() {
	test_mkdir
	echo 'foo' >"${mp}/d/r"
	echo 'bar' >"${dev_a}/d/r"
	mv "${dev_a}/d/r" "${dev_a}/d/bad"
	test "$(ls "${mp}/d")" == 'r'
	test "$(<"${mp}/d/r")" == 'foo'
}
test_resiliance_lfile() {
	test_lfile_write
	echo 'bad' >"${dev_a}/r"
	cmp -s "${test_tmp}/r" "${mp}/r"
}

resiliance_tests='test_resiliance_reg test_resiliance_lnk '\
'test_resiliance_dir test_resiliance_lfile'

test_resiliance() {
	run_tests "${resiliance_tests}"
}

test_restoration_reg() {
	test_write
	echo 'bad' >"${dev_a}/r"
	cat "${mp}/r" >/dev/null
	test "$(<"${dev_a}/r")" == 'foo'
}
test_restoration_lnk() {
	test_symlink
	ln -sf 'bad' "${dev_a}/l"
	readlink "${mp}/l" >/dev/null
	test "$(readlink "${dev_a}/l")" == 'foo'
}
test_restoration_dir() {
	test_mkdir
	echo 'foo' >"${mp}/d/r"
	echo 'bar' >"${dev_a}/d/r"
	mv "${dev_a}/d/r" "${dev_a}/d/bad"
	ls "${mp}/d" >/dev/null
	test "$(ls "${dev_a}/d")" == 'r'
	test "$(<"${dev_a}/d/r")" == 'foo'
}
test_restoration_missing_reg() {
	test_write
	rm "${dev_a}/r"
	cat "${mp}/r" >/dev/null
	test "$(<"${dev_a}/r")" == 'foo'
}
test_restoration_lfile() {
	test_lfile_write
	echo 'bad' >"${dev_a}/r"
	cat "${mp}/r" >/dev/null
	cmp -s "${test_tmp}/r" "${dev_a}/r"
}

restoration_tests='test_restoration_reg test_restoration_lnk '\
'test_restoration_dir test_restoration_missing_reg test_restoration_lfile'

test_restoration() {
	run_tests "${restoration_tests}"
}

test_nonexistent() {
	! cat "${mp}/nonexistent" >/dev/null 2>&1
	! ls "${mp}/nonexistent" >/dev/null 2>&1
}
test_broken_lnk() {
	ln -s 'nonexistent' "${mp}/l"
	! cat "${mp}/l" >/dev/null 2>&1
}
test_not_a_reg() {
	test_mkdir
	! cat "${mp}/d" >/dev/null 2>&1
	ln -s 'd' "${mp}/l"
	! cat "${mp}/l" >/dev/null 2>&1
}
test_not_a_dir() {
	test_write
	! ls "${mp}/r" >/dev/null 2>&1
	ln -s 'r' "${mp}/l"
	! ls "${mp}/l" >/dev/null 2>&1
}
test_not_a_lnk() {
	test_write
	! readlink "${mp}/r" >/dev/null 2>&1
	test_mkdir
	! readlink "${mp}/d" >/dev/null 2>&1
}

negative_tests='test_nonexistent test_broken_lnk test_not_a_reg '\
'test_not_a_dir test_not_a_lnk'

test_negatives() {
	run_tests "${negative_tests}"
}

test_permission_cat() {
	test_chmod
	! su -l -s /bin/sh "${unpriv_user}" -c "cat ${mp}/r >/dev/null 2>&1"
}

test_permission_append() {
	test_chmod
	! su -l -s /bin/sh "${unpriv_user}" -c \
	    "echo bar >>${mp}/r" >/dev/null 2>&1
}

test_permission_ls() {
	test_mkdir
	touch "${mp}/d/r1"
	touch "${mp}/d/r2"
	chmod 0700 "${mp}/d"
	! su -l -s /bin/sh "${unpriv_user}" -c "ls ${mp}/d >/dev/null 2>&1"
}

test_permission_mv() {
	test_chmod
	! su -l -s /bin/sh "${unpriv_user}" -c \
	    "mv ${mp}/r ${mp}/r2 >/dev/null 2>&1"
}

test_permission_rm() {
	test_chmod
	! su -l -s /bin/sh "${unpriv_user}" -c "rm -f ${mp}/r >/dev/null 2>&1"
}

test_permission_chmod() {
	test_chmod
	! su -l -s /bin/sh "${unpriv_user}" -c \
	    "chmod 0777 ${mp}/r >/dev/null 2>&1"
}

test_permission_chown() {
	test_chmod
	! su -l -s /bin/sh "${unpriv_user}" -c \
	    "chown ${unpriv_user} ${mp}/r >/dev/null 2>&1"
}

permission_tests='test_permission_cat test_permission_append '\
'test_permission_ls test_permission_mv test_permission_rm '\
'test_permission_chmod test_permission_chown'

test_permissions() {
	run_tests "${permission_tests}"
}

all_tests='test_basics test_resiliance test_restoration test_negatives '\
'test_permissions'

test_all() {
	for t in ${all_tests}
	do	echo ${t}
		${t}
	done
}

testsuite_init
for a in crc32 md5 sha1
do	echo "Checksum algorithm: ${a}"
	chk_alg="${a}"
	test_all
done
testsuite_final
echo 'All tests passing.'
exit 0
