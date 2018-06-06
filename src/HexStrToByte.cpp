// The HEX values needs to be separated with any tyep of char, i.e: 0xFF,0x0f || \xFF\x0f || FF 0f e etc...
    static std::vector<BYTE> HexStrToByte(const std::basic_string<TCHAR> &_hexStr) {
    std::vector<BYTE> _byte;

    if (_hexStr.length() != 0) {
        std::basic_string<TCHAR> _hex;

        for (UINT32 i = 0; i < _hexStr.length(); i++) {
            _hex = _hexStr.substr(i, 2);
  
            if ((_hex[0] >= '0' && _hex[0] <= '9' || ((_hex[0] >= 'A' && _hex[0] <= 'F') || (_hex[0] >= 'a' && _hex[0] <= 'f'))) &&
                (_hex[1] >= '0' && _hex[1] <= '9' || ((_hex[1] >= 'A' && _hex[1] <= 'F') || (_hex[1] >= 'a' && _hex[1] <= 'f')))) {
                #if !UNICODE
                _byte.push_back(strtoul(_hexStr.substr(i, 2).c_str(), 0, 16));
                #else
                _byte.push_back(wcstoul(_hexStr.substr(i, 2).c_str(), 0, 16));
                #endif
             }
         }
         
         return _byte;
    }
    
    return _byte;
}
