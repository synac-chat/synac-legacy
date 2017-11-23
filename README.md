# synac

## Open Beta

**WARNING:** The client code currently sucks for anything other than the minimal front-end.  
I should rewrite it in a more async manner.

After a lot of work in a closed alpha, the first beta version is ready.  
Breaking changes are now less frequent, and you might wanna start developing bots or front-ends.  
Bugs are likely to be found, as I am known to accidentally try to access a channel by a user's ID or such.  
Not all of the below points are implemented, and they might change around.

If you don't feel like hosting a server or just wanna hang out with other beta testers,
check out the official testing server:

**IP**: krake.one  
**Public key hash**: `C9F6251FA50892B3877ACECA523ACFD925CAA7D9FA245D9C50DD00083A39F199`

--------------------------------

This is the beginning of a new chat protocol and application.  
It's hugely inspired by IRC, but it's easier.

Let's compare!  

## Why not IRC?

I just tried and already love IRC, but it's too complicated to set up and configure for somebody like me.  
Differences from IRC:

- Bot accounts should be marked so you can see if somebody is a bot.
- Channels can only be created with a specific permission.
- Each account gets a (resettable) token. This token is stored on the client and used to log in with, instead of the password.
- Message logs are kept by default.
- Most configuration is done from inside the application itself.
- Nicknames are claimed using a password by default.
- Private messages are end-to-end encrypted

## Why not Discord?

Honestly, this whole thing is basically a Discord copy-cat.  
Differences from Discord:

- Bot accounts have a separate permission from @everyone, so you can deny bots the ability to read message easier.
- No terms of service. Do what you want.
- No voice support.
- Open source.
- Private messages are end-to-end encrypted
- Self-hosted. You will have to set up the server yourself (this is good for security.)
- You can not only allow, but also deny a permission. Meaning you won't struggle with trying to make a "muted" role.

## Is this going to replace Discord?

Never. Probably.  
People want centeralized servers, which is exactly what this is against.
