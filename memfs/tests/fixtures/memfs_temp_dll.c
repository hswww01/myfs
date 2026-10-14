/* Harmless DLL fixture for memory-mapped image loading from the RAM volume. */
__declspec(dllexport) int memfs_probe_value(void) {
	return 73;
}
