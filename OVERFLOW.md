What happens when you have **too many** messages?

### Overflow

According to the protocol, IDs are stored in a either pointer-sized integer (see `usize`).  
This means IDs go as far as they can on the system's resources, and cannot really be changed to go higher.

However, the official implementation uses SQLite, and is therefor limited to a 64-bit signed integer (see `i64`).  
This means that the amount of messages are limited to 9,223,372,036,854,775,807.  
Once you reach that, you are in for "undefined behavior".

### Undefined behavior

Calm down, we don't mean "undefined behavior" as trying to access an element outside of an array bounds in C.  
We mean "behavior we can estimate, but don't know for sure, and don't care".

The worst that could happen is a program crash.  
What will probably happen is that it will work fine.  
Let's take a look:

When SQL increments IDs over 9,223,372,036,854,775,807, it *should* wrap around to -9,223,372,036,854,775,808.  
Then this program tries to convert the ID to a `usize`. A usize has to be more than 0.  
So that wraps back around to 9,223,372,036,854,775,808.  
*In theory*, this means that it should work fine up to 18,446,744,073,709,551,615!  
After this number is reached, you should start seing IDs overlapping.  
The very first message is deleted and the new one is made.  
Then the very second one. Et.c. *In theory.*

### Will I ever hit this limit?

No. Let's put this into perspective.  
As I'm writing this, the current amount of *seconds* since January 1 1970 is 1505578225.  
That's 0.00000000016% of the minimum limit, and 0.00000000008% of the likely limit.  
In fact, even if you sent a message per second, it would take you more than 100,000,000 years to reach the limit.
