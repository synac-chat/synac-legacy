All these limits are in bytes. If they were characters they would have to be a lot smaller
since some characters take up a lot of space.

## Soft limits

Since we want the server to be customizable, we put values in a config file.
Though, don't panic! Everything has good default values that you don't need to change
unless you want to.

## Hard limits

Because the packet size is limited to a 16-bit unsigned integer size (65535),
somebody could send a really large message to the server and it would fail to deliver.

To prevent these... unfunny pranks... we set hard limits you may not bypass.

## Fancy Table

|---------------------+------------+--------------------|
| Type                | Hard limit | Default Soft limit |
|---------------------+------------+--------------------|
| Username length     | 128        | 32                 |
| Channel name length | 128        | 32                 |
| Attribute name      | 128        | 32                 |
| Attribute amount    | 2048       | 128                |
| Message length      | 16384      | 1024               |
|---------------------+------------+--------------------|

## Bypassing?

In the official server, these limits are only checked on set.
So, you can bypass these limits by manually changing the SQLite.  
Although, you *really* shouldn't...
