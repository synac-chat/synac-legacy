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

*.. means "between (inclusive)" in this case*

| Type                  | Hard limit | Default Soft limit |
| --------------------- | ---------- | ------------------ |
| Username length       | 1..128     | 2..32              |
| Channel name length   | 1..128     | 2..32              |
| Attribute name length | 1..128     | 2..32              |
| Attribute amount      | 2048       | 128                |
| Message length        | 1..16384   | 1..1024            |

## Bypassing?

In the official server, these limits are only checked on set.
So, you can bypass these limits by manually changing the SQLite.  
Although, you *really* shouldn't...
