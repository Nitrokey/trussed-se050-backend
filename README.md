Trussed backend leveraging the SE050 secure element
===================================================

This backends reimplements the assymetric cryptography APIs from [Trussed](https://github.com/trussed-dev/trussed) using the SE050 secure element.
It also implements secure PIN handling following the [trussed-auth](https://github.com/trussed-dev/trussed-auth) APIs, as well as RSA operations (which aren't part of the core trussed API).

Differences with the main implementations
-----------------------------------------

- The `UnwrapKey` syscall cannot be used after the key has been deleted.
As such, the key needs to be "cleared" with the `Clear` syscall if one wants to unwrap it again, leaving the metadata required for unwraping.

- Public keys obtained through `DeriveKey` can only be valid for as long as the original private key they are derived from.

