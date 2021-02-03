# Changelog

## 2021-02-02
### Added

- Parameter *error: invalid_request* added to the Authorization server *400 Bad Request* response when the request payload doesn't match the model.
- Added headers to server response: 'Cache-Control': 'no-store', 'Pragma': 'no-cache', 'Referrer-Policy': 'no-referrer'.

### Fixed
- Source IP address is not defined correctly when using Cloudflare.
