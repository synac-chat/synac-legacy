# schmic

*Warning: Not everything here is implemented yet.  
Development is going slowly but surely forwards.*

This is the beginning of a new chat protocol and application.  
It's hugely inspired by IRC, but it's easier.

Let's compare!  

## Why not IRC?

I just tried and already love IRC, but it's too complicated to set up and configure for somebody like me.  
Differences from IRC:

- Bot accounts should be marked so you can see if somebody is a bot.
- Channels can only be created with a specific permission.
- Each account gets a (resettable) token. This token is stored on the client and used to log in with, instead of the password.
- Message Logs are kept by default.
- Most configuration is done from inside the application itself.
- Nicknames are claimed using a password by default.
- Optionally send E2E encrypted messages.

## Why not Discord?

Honestly, this whole thing is basically a Discord copy-cat.  
Differences from Discord:

- Bot accounts have a separate permission from @everyone, so you can deny bots the ability to read message easier.
- No terms of service. Do what you want.
- No voice support or direct messages.
- Open source.
- Optionally send E2E encrypted messages.
- Self-hosted. You will have to set up the server yourself (this is good for security.)
- You can not only allow, but also deny a permission. Meaning you won't struggle with trying to make a "muted" role.

## Is this going to replace Discord?

Never. Probably.  
People want GUIs, centeralized servers and similar,
all which is exactly what this is mostly against.

However, it may some day run side by side with Discord.
