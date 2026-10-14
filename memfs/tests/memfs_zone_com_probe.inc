/* The same COM object Windows uses to persist security-zone information.
 * Tests write Internet ZoneId=3; they never disable security checks/unblock. */
static void test_zone_com(void) {
    WCHAR file[2048]; IZoneIdentifier *zone=NULL,*loaded=NULL;
    IPersistFile *persist=NULL,*reader=NULL; DWORD id=0;
    HRESULT init=CoInitializeEx(NULL,COINIT_MULTITHREADED);
    CHECK(SUCCEEDED(init)); if(FAILED(init))return;
    path(file,_countof(file),L"com-zone.txt");stream_write(file,"safe test fixture",17,CREATE_NEW);
    HRESULT hr=CoCreateInstance(&CLSID_PersistentZoneIdentifier,NULL,CLSCTX_INPROC_SERVER,
        &IID_IZoneIdentifier,(void**)&zone);
    CHECK(SUCCEEDED(hr));
    if(zone) {
        CHECK(SUCCEEDED(IZoneIdentifier_SetId(zone,URLZONE_INTERNET)));
        hr=IZoneIdentifier_QueryInterface(zone,&IID_IPersistFile,(void**)&persist);
        CHECK(SUCCEEDED(hr));
        if(persist)CHECK(SUCCEEDED(IPersistFile_Save(persist,file,TRUE)));
    }
    hr=CoCreateInstance(&CLSID_PersistentZoneIdentifier,NULL,CLSCTX_INPROC_SERVER,
        &IID_IZoneIdentifier,(void**)&loaded);
    CHECK(SUCCEEDED(hr));
    if(loaded) {
        hr=IZoneIdentifier_QueryInterface(loaded,&IID_IPersistFile,(void**)&reader);
        CHECK(SUCCEEDED(hr));
        if(reader) {
            CHECK(SUCCEEDED(IPersistFile_Load(reader,file,STGM_READ)));
            CHECK(SUCCEEDED(IZoneIdentifier_GetId(loaded,&id)) && id==URLZONE_INTERNET);
        }
    }
    if(reader)IPersistFile_Release(reader);
    if(persist)IPersistFile_Release(persist);
    if(loaded)IZoneIdentifier_Release(loaded);
    if(zone)IZoneIdentifier_Release(zone);
    stream_expect(file,"safe test fixture",17);
    WCHAR ads[2200];stream_path(ads,_countof(ads),file,L"Zone.Identifier");
    CHECK(stream_exists(ads));CHECK(DeleteFileW(file));
    CoUninitialize();
}
