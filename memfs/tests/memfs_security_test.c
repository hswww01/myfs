#include "memfs_core.h"
#include <sddl.h>
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(x)                                                                                                       \
	do {                                                                                                               \
		if (!(x)) {                                                                                                    \
			++failures;                                                                                                \
			fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x);                                                            \
		}                                                                                                              \
	} while (0)

static void test_descriptor_ownership(void) {
	Memfs* fs = NULL;
	MemfsNode *node = NULL, *bad_node = NULL;
	PSECURITY_DESCRIPTOR source = NULL;
	SECURITY_DESCRIPTOR absolute, invalid;
	SECURITY_DESCRIPTOR_CONTROL control;
	DWORD revision, size;
	PSID owner = NULL, group = NULL, result_owner = NULL;
	PACL acl = NULL;
	BOOL present, def;
	MemfsSecurity* saved;
	BYTE owner_copy[SECURITY_MAX_SID_SIZE];
	CHECK(memfs_create(8ULL << 20, L"ACL_TEST", &fs) == MEMFS_OK);
	if (!fs)
		return;
	CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;WD)", SDDL_REVISION_1,
															   &source, NULL));
	if (!source)
		goto cleanup;
	CHECK(GetSecurityDescriptorOwner(source, &owner, &def));
	CHECK(GetSecurityDescriptorGroup(source, &group, &def));
	CHECK(GetSecurityDescriptorDacl(source, &present, &acl, &def));
	CHECK(CopySid(sizeof(owner_copy), owner_copy, owner));
	CHECK(InitializeSecurityDescriptor(&absolute, SECURITY_DESCRIPTOR_REVISION));
	CHECK(SetSecurityDescriptorOwner(&absolute, owner, FALSE));
	CHECK(SetSecurityDescriptorGroup(&absolute, group, FALSE));
	CHECK(SetSecurityDescriptorDacl(&absolute, TRUE, acl, FALSE));
	CHECK(memfs_node_create(fs, fs->root, L"absolute", false, 0, &absolute, 0, &node) == MEMFS_OK);
	if (!node)
		goto cleanup;
	CHECK(GetSecurityDescriptorControl(node->security->data, &control, &revision) && (control & SE_SELF_RELATIVE));
	CHECK(GetSecurityDescriptorControl(&absolute, &control, &revision) && !(control & SE_SELF_RELATIVE));
	LocalFree(source);
	source = NULL;
	memset(&absolute, 0xcc, sizeof(absolute));
	CHECK(IsValidSecurityDescriptor(node->security->data));
	CHECK(GetSecurityDescriptorOwner(node->security->data, &result_owner, &def) && EqualSid(result_owner, owner_copy));

	saved = node->security;
	memset(&invalid, 0, sizeof(invalid));
	CHECK(memfs_node_replace_security(node, &invalid, sizeof(invalid)) == MEMFS_ERR_INVALID);
	CHECK(node->security == saved);
	CHECK(memfs_node_create(fs, fs->root, L"invalid", false, 0, &invalid, 0, &bad_node) == MEMFS_ERR_INVALID);
	CHECK(bad_node == NULL && memfs_dir_lookup(fs->root, L"invalid") == NULL);

	CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FA;;;BA)", SDDL_REVISION_1, &source,
															   &size));
	if (!source)
		goto cleanup;
#ifndef NDEBUG
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_SECURITY, 0, 1);
	CHECK(memfs_node_replace_security(node, source, size) == MEMFS_ERR_NO_MEMORY);
	CHECK(node->security == saved && IsValidSecurityDescriptor(saved->data));
	memfs_allocator_test_clear_failures();
#endif
	CHECK(memfs_node_replace_security(node, source, size) == MEMFS_OK);
	CHECK(node->security != saved && IsValidSecurityDescriptor(node->security->data));
cleanup:
	memfs_allocator_test_clear_failures();
	if (source)
		LocalFree(source);
	if (node) {
		CHECK(memfs_node_unlink(node) == MEMFS_OK);
		memfs_node_close(node);
	}
	memfs_destroy(fs);
}
static void test_small_relative_descriptor(void) {
	Memfs* fs = NULL;
	MemfsNode* node = NULL;
	SECURITY_DESCRIPTOR absolute;
	BYTE relative[64];
	DWORD size = sizeof(relative);
	CHECK(memfs_create(8ULL << 20, L"NULL_DACL", &fs) == MEMFS_OK);
	if (!fs)
		return;
	CHECK(InitializeSecurityDescriptor(&absolute, SECURITY_DESCRIPTOR_REVISION));
	CHECK(SetSecurityDescriptorDacl(&absolute, TRUE, NULL, FALSE));
	CHECK(MakeSelfRelativeSD(&absolute, relative, &size));
	CHECK(GetSecurityDescriptorLength(relative) == sizeof(SECURITY_DESCRIPTOR_RELATIVE));
	CHECK(memfs_node_create(fs, fs->root, L"null-dacl", false, 0, relative, 0, &node) == MEMFS_OK);
	if (node) {
		BOOL present, def;
		PACL acl = (PACL)(uintptr_t)1;
		CHECK(GetSecurityDescriptorDacl(node->security->data, &present, &acl, &def) && present && acl == NULL);
		CHECK(memfs_node_unlink(node) == MEMFS_OK);
		memfs_node_close(node);
	}
	memfs_destroy(fs);
}
int main(void) {
	test_descriptor_ownership();
	test_small_relative_descriptor();
	printf("memfs_security_test: %s\n", failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}
