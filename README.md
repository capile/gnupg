# PGP (Gnupg) for PHP

This package replaces PECL php-gnupg package by providing the same funcionality and extending support for GPG 2. 

Some methods are still under development, more specifically the ones related to key/message signing and verification.

## Installation

Installation should be done via composer.

## Testing

If you'd like to test your instance, use composer to install the require-dev packages and run:

```
composer test
```

It can also be linked to a static installation of gnupg, in case your OS is using an outdated version without support for new features, like Elliptic curves. For these tests you can load a default configuration by copying the file `test-configuration-pgp.json-example` to `test-configuration-pgp.json` and adjusting your configuration parameters.