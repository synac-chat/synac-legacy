# unnamed

This is the beginning of a new chat protocol and application.  
It's hugely inspired by IRC, but it's easier.

Let's compare!  

## Why not IRC?

I just tried and already love IRC, but it's too complicated to set up and configure for somebody like me.  
Differences from IRC:

- Bot accounts should be marked so you can detect if somebody is a bot.
- Channels can only be created with a specific permission.
- Logs are kept by default.
- Most configuration is done from inside the application itself.
- Nicknames are claimed using a password by default.
- Optionall send E2E encrypted messages.
- Passwords are sent in tokens, to store them safely on the client.

## Why not Discord?

Honestly, this whole thing is basically a Discord copy-cat.  
Differences from Discord:

- Bot accounts benefit from a command API which makes it easy and consistent to parse.
- Bot accounts can only see messages they're allowed to.
- Self-hosted. You will have to set up the server yourself (this is good for security.)
- No terms of service. Do what you want.
- No voice support or direct messages.
- Open source.
- Optionally send E2E encrypted messages.

## Is this going to replace Discord?

Never. Probably.  
People want GUIs, centeralized servers and similar,
all which is exactly what this is mostly against.

However, it may some day run side by side with Discord.

## Goals

- Obviously having it work like expected.
- Replacable client front-ends.
- ncurses.
