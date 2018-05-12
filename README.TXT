Modern crypto is based on assumptions that favor large, well-funded
groups such as NSA. Snowden gave their game away telling Poitras “Assume
your adversary is capable of checking one trillion passwords per second 
against a file. NEVER use a password that has been exposed on the internet“.* 
Why go to the bother of trying passwords if it is easir to crack the code?
So collecting and testing passwords is easier and cheaper than cracking
ciphers or working back through known ciphers to the password.

Further, it seems to me that the entire crypto community has been
avoiding the obvious, very simple, approaches to solid crypto which make
merely guessing a password useless in breaking the cypher, you need the
unique cypher program, also.

The assumptions that current crypto systems are based upon is exactly
what favors NSA :

(0)There will be a large amount of traffic on any standard, so it must be
unbreakable.

(1) The logistical difficulty of distributing one-time pads means those
cyphers, known to be unbreakable, can't be used.

(2) Pseudo-random number generators of cryptographic quality are not
sufficient. Things I read never say that, but emphasize that PRNGs have
cycles that are hard to prevent and can't be predicted, so  it is very
difficult to write good PRNGs, more difficult to write crypto-quality
PRNGs.

(3) Standard mechanisms can't use many CPU cycles, which are in short
supply. This assumption is obviously no longer true, when a cell phone
has more power than the first Cray 1.

(4) Passwords are therefore the security of the total system.

Thus, the major crypto mechanisms are unbreakable, e.g. AES with its
256-bit key space and 14 cycles of mixing key and plaintext. But, NSA
likes that unbreakable cypher, because it fixes in place the use of both
standards and passwords. Small-logic standards mean testing passwords
against files can be accelerated and automaed. Passwords are a product
of human minds and culture, and those have many regularities, so are
much easier to attack than the unbreakable cypher.

To attack the password side of the equation, NSA has** automated the
testing of passwords for encrypted files, and can run 1T passwords per
second against the intercepts they receive, by the implications of
Snowden's comment. ***

Thus, the unbreakable standards favor NSA because NSA can automate the
cryptoanalysis to allow attacking the password, a very much smaller
search space. It may be expensive, but it is also not possible for many
organizations to do the required engineering development for the ASICS,
and is NSA's competitive advantage on a world stage. The fact that it
mostly won't work against State actors who use better mechanisms for
translating passwords to keys is another reason NSA focuses on individuals
and economic espionage.

I think it is easy to design a crypto system that uses excellent
cryptology mechanisms but doesn't perform in the a standard way, one
version of the program to another, nor one password to another on one
version of the code. That design would be resistant to any automated
cryptoanalysis except purely statistical attacks, and make hardware
acceleration of attacks on the keys economically infeasible, both the
size of the engineering project and the amount of hardware needed.

One base of such a system is a PseudoRandom Number Generator + XOR.
XOR is a bit-level modulo operation, meaning that one of the 2 bits must
be known to know the other. If the PRNG can't be predicted, and also
produces a random-enough stream of bits, that is equivalent to a one-time
pad, provably unbreakable from information theory.

There are many possible crypto-quality PRNGs, many possible ordinary
PRNGs that could compose the crypto-quality PRNGs, and many different
hashes that can be used to initialize them and convert a password to an
index selecting one of those functions from a list. They can be
initialized in many different ways, the class init() function for each
will use a member of the list of hashes, again dependent upon the
password.

The cryptographic PRNGs I provide choose N separate ordinary PRNGs using
a variety of algorithms. They use one to choose bits of the others to make
up the output byte. Further, the particular ordinary PRNGs are selected
from a list using different hashes of the password, and initialized by
copying bits from the 4K of random bytes in a constant in the program.

Every program can generate new programs dependent on the password used.
For any program, using the same password will generate the same output
program, that is deterministic.  However, the new program will be unique
with a different password. Every different program will generate a
different set of operations for encryption-decryption when using the
same password.

New versions of the program change the random data and the ordering of
the list of crypto-quality PRNGs, the list of ordinary PRNGs and the
list of hashes.

Each new version of the program is identified by the hash value of its
text appended to the name.  Each program can only communicate with
identical versions of the program and using the same password. That is,
both program and key must be distributed for first use.

This program uses the fact that we can change these programs faster than
any opponents can crack them, so once we have a pair distributed, NSA
can't keep up. Any time we wish, e.g. at intervals or after N million
characters are transmitted, we each generate a new program and continue
with the same passwords.  The new programs and old password will produce
entirely different encryptions of a standard plain text.  Thus, the
program is as important as the password.

Each program is unique because of 4096 random byte values in a constant
array and because lists of crypto-quality PRNG functions, lists of
ordinary PRNG functions and lists of hash functions are different in
newly-generated programs, based on the password used to generate the
program.  That deterministically makes identical programs on each side,
but different than any prior program would have produced for the same
password. It is infeasible to use a current program to obtain previous
programs, even if the password used to generate one is known, perfect
forward secrecy.

Every security-sensitive program must be part of a deeply layered
defense.  I put in some of the checks I think are standard, e.g. encoded
the program's hash in the name, and check that every startup, checking
permissions, ... there must be many more.  The program refuses to run if
anything is awry.  Better no communications than compromised
communications.

The program is attached below, there are many more comments in the code.
Most important, this is a proof of concept, and I am no programmer of
secure systems.  My testing has been light. Practical programming for
secure applications is a big area, and I don't have time to learn all
that, so I wouldn't trust this for anything serious yet.

So the implementation can be critiqued, but I believe the concepts
behind the implementation are solid.

I would love to have someone(s) to take this idea and make a serious
open source project from it. The code is not copyrighted, do with it as
you will.

*My lawyer said I can't plagarize myself, so you need to read the
original articles for that bit of reasoning, here and here.

Also, probably every programmer who gets interest in cryptology has a
great idea for a crypto system, and most are bunk.  I can't be sure mine
is not bunk, as I am not a cryptologist. However, I am enough of a
computer scientist and software engineer to understand the basics, and
this is solid computer science and information theory.

I predict the professionals won't like this, because it puts producing
neat versions of crypto codes back into mere programmer's hands and
secrecy back into all of our affairs.

To be sure, this approach has downsides, e.g. versions as part of
programs will be an operational problem, so password managers, etc. need
to be improved to go along with it.  But, if you want your secrets safe
from NSA, some version of this is the way to go.

**I say 'NSA has' or 'NSA likes', but I mean, of course, it is logical
that NSA would have or like, reasoning from the available evidence. Just
to remind you, an implication of Snowden's comment is that NSA breaks
the unbreakable codes, routinely. Did that happen by accident?

***OK, a new version, so I am not plagiarizing myself.

1 trillion is a BIG number, 10,000 variants of each of the 2 million words
and names and well-known scraps of poetry for 50 languages. AES and other
algorithms are designed to be computationally complex, and so slow. A
fast processor maybe could do a few 10s of thousand of passwords per
second against a single file, so 1T would require millions of processor
cores, not economically feasible. NSA must reach that level of attempts
per second by using Application Specific Integrated Circuits which use
pipelines of the 14 layers of AES's mixing to obtain parallelism, each
calculation may be stepping through hundreds of stages in the pipeline,
one after another.

I think it unlikely there are more than a few 10s of billions of
passwords that have ever been used on the net, what with redundancies,
so a few percent of 1T. That allows more files to be checked per day.
The physical implementation is likely that these ASICS show up in the
memory space,  the control software only has to write into consecutive
words to begin the hardware's processing. The parameters would be the
address of the message, an index into the language statistics needed to
check deciding whether the password worked or not, the length of the
message to process, and the hash of the password. ASICs can include
32-bit processors between different buffer memories in that ASIC
hardware, for combining hardware acceleration with normal firmware, in
parallel with the host system's processors.

A few thousand clock cycles later, after the shortest length of message
necessary to decide 'decrypted' or 'not decrypted', or 'maybe decrypted'
the output text has been processed into statistics on a dozen aspects of
the message snippets, or run through a neural net that computes a 'yes',
'no' or 'maybe' for the file.

An ASIC could clock at 1 GHz.  Assuming 10,000 clocks per file, a single
ASIC could process 100,000 files per second. A single unit could process
multiples of a 1000 files per minute. Handling more files merely means
more hardware and network bandwidth, normal scaling, so this design
easily keeps ahead of the world's encrypted traffic.

Add computers deciding what encrypted files are passed to which of the
pipelines,  easy because all of the standards leave signatures in the
files, and NSA will break encrypted traffic unless the individual doing
the encryption is very careful in generating and using passwords. State
actors can do that reliably, but probably not individuals.

At least so long as people use AES and the other unbreakable standards
and depend on human-generated passwords.  Fix one or the other, and NSA
gets nothing.  I can't do anything about the password problem for
general use, but this is an alternative to their unbreakable standards.

There must be a proof of the difficulty of determining the prng
sequence being proportional, at least, to the number of bits
of entropy multiplied by the number of operations producing entropy.

Empiricially, my simple PRNGs pass dieharder, of course the
crypto-quality PRNGs must have exponentially longer cycles,
exponential in the number of simpler PRNGs that compose them.
thus determing the sequence must be very, very much harder
than the difficulty of computing it.  Another of the things
not discussed in the crypto literature, at least not the
relatively simple stuff I have read, and there is no sign
of such thought in crypto code that I have seen discussed.

Consider the idea of giving a code breaker the program, the
Encyclopedia Britannica ( electronic version) and that file
encrypted with that program.  The task is to find the
 password.

I believe that is doable with AES and the other
simple-mechanisms, but not with anyrhing more complex. This is
a result of far more mixing of the entropy in the individual
program with the password before applying that randomness to a
cipher mechanism, which mechanism is guaranteed secure.

If you make something regular, you make it breakable, given
some level of tech.  NSA standards have made things regular. Clearly
NSA have developed the tech to compute AES fast enough to make
password attacks feasible.  Irregular is good in crypto.

------

Do I think this is breakable? Maybe, but only with considerable
effort and needing very large amounts of traffic.

Individual elements mostly pass Dieharder, at worst 5 'weak' out of >100
tests. The combination of the elements do better, 100 tests pass.

Very likely NSA has better measures of randomness than Dieharder
has, but I don't think that matters, because cryptographic PRNGs are NOT
predictable, and a mere weakness in their number stream is not (I think,
but am not a cryptologist) enough to know for certain), enough to read
the encrypted message.

It is important to state that the implementation here is NOT 'security
by obscurity'. It is security by cryptographic quality PRNGs + XOR,
known to be unbreakable.

The overly-elaborate and very slow mechanisms entirely prevent, I believe, any
password attacks because that is computationally infeasible. The
mechanism is not a simple one that can be unrolled into a hardware
pipeline, so no ASIC speedup is possible.

Any weaknesses in a PRNG will produce non-random cipher streams, and an
attacker would combine that with probabilities of individual characters
to understand the mechanism. But it doesn't help if the mechanism is
deep and opaque.

Given the plaintext and ciphertext encyclopedia and the program that
encrypted it, I assert that it is computationally infeasible to work
back to the password because of the depth of the mechanism and the many
branch points in the code. That was the goal of this program.

Add to that the evolution of lines of descent via the ease of adding
computationally-equivalent functions and each program producing new
versions of itself, combined with limiting traffic for each version,
and NSA's problem is impossible.

----------------
How the program works and why.

First, every file has tests that are used to validate the functions,
generally using dieharder as validation.

Evodieharder automates testing of those, to a maximum of the number of
cores you want to dedicate to those tests. Tests with dieharder use 100%
of a processor core.

Programs begin by being assembled

-----------------------
Future features :

Is this program secure?  Very good question, but that can't be answered
because it is attempting to prove 'it can't be cracked', a negative.

However, we can consider a crypto element to be a noise source in a
communication link, and consider how effectively it masks the data being
transmitted. That is, what is the correlation between the signal before
masking and the masked signal?  That is a different measure than
randomness, potentially powerful. No doubt, NSA's understanding of those
measures far exceeds the best I will ever have.

OTOH, I know how to compute entropy, have many test of whether the
implementations of generating psuedorandom number generators are OK
(there is no such thing as perfect when discussing random), and XOR
is theoretically solid, a bit-level modular addition.

Given enough different PRNGs and hashes to mask the original signal, I
can then dilute that cryptotext with output of other PRNGs, mixing
controlled by yet other PRNGs. Thusly, the bit-rate of plain text in
the crypto-text + random data string can be made as low as required by
any level of paranoia. If the password determins the PRNG that pulls
bytes out of the file and also decrypts them, it is easy to have a cover
file that you can expose, if necessary.

(I haven't put that last bit in, it is the last to be done, after I am
sure the rest of the code is solid and probably as a separate program.)

Nevertheless, the bit-rate could be > 0.  Given enormous amounts of
cypertext, specialized hardware and sufficient motivation, NSA may have
the power to break my best effort. But the size of the bit-level
conditional logic would make that very expensive and it would take a
long time to run enough traffic through it. That would have a low
payoff, because changing the password changes the mechanism being used.

I don't think this is breakable (at least theoretically, implementation
may have produced explitable flaws), but it doesn't matter. As a community,
we have 2 more tactics to counter NSA, both forms of evolution.

First, new functions can be generated.  Because dieharder is the
acceptance test for prngs and hashes, we can know that each of them is
functionally correct before they are added to the their function
list. Every such function increases the problem of decryption.

Second, individuals can agree to generate a new version of the program
they are jointly using, using the identical password to do so.  The new
program will have a different Random Number Table and different
orderings of the various lists.  A good time to do this would be well
before an opponent could accumulate enough ciphertext to begin to work
out the encryption methods.

In biological evolution, variation is needed for selection to occur,
genetic drift has an effect exponentiallly stronger as groups ge
smaller. Our fitness function is dieharder.

For interative communications, we need to add another level, this is
evochat.py, not very sophisticated and has an annoying bug. That is not part
of this initial release, tho the code may be there.

-------------
Design Notes for the Chat feature :

0) We need a first message to ensure that we are synced.  That should be
a random number, chosen independently by each side, and sent to the
other.  The receiver encrypts and sends it back. It is, in a sense,
chosen plain text, an insight into the PRNG's workings.  But, we have
confidence in that, right? 16 bytes isn't going to give away much
information. We could obscure that in various ways, also. Complexity
that prevents putting any decryption into an ASIC.

1) There is a problem here, it seems to me, and finding this kind
of issue is why I am writing the program, it is QA on thinking.

Problem is, the first N bytes, the random number that comes from
the other side is deterministic wrt the PRNG. The PRNG will be
initialized every time the same way, and must be to exchange random
numbers containing local entropy, outside of the determinist
program's random but predictable stream.  At least predictable
if you have the code to the program. so if code, but not password,
the attacker is still in the dark due to the complexity of the
initialization of the LCNPRNG.

The other implication of inline protocols is that it offers
another way of adding complexity, e.g. agreeing to double the
number of lower-level prngs' cycles per bit returned, etc.  That
is another aspect of the idea that cryptographic defense can
keep ahead of offense, no matter how weak the initial encryption
and shared secret. That needs an in-line message and protocols,
e.g. fallback to the last working level and so many K of good
communication before any new params sent to change internal
states, begin a new PRNG on the links, etc.

---------------------
Thinking about all of this, I don't believe NSA breaks any reputable
ciphers. The very finest lithography, full-custom design to run AES is
probably capable of 2GHz, assume 100 clocks startup time, it can spit
out an answer 10Mps. But it is just a chip and some memory on a shared
buss, those can be replicated for 10s of $s and scaled factors of 10 
without losing effectiveness.

But that just means don't use small-mechanisms ciphers, don't use
standards and do use theoreitically solid mechanisms to compute new
mechanisms as it functions. Waste enough processor power generating
randomness from randomness in enough different ways, and you can make an
attacker's job impossible.
-------------
After I understood all this above, I found this article :

https://eprint.iacr.org/2018/212.pdf

It got too hard for me about the 3rd page, so I didn't read all of it.

It describes how to boostrap a subliminal communications channel using
steganography to hide the messages. Steganography depends on sprinkling
evenly distributed bit-strings through the covering document as part of
the 'noise'. on sprinkling evenly distributed bit-strings through the
covering document as part of the 'noise'. 

Evocrypt is about 150K bytes just now, 1.2M bits. That is a small
photography, I can see why they use photos, so many bits relative to
other documents. But the idea is the same as dilluting a file in
noise and mixing more than oen file into some other digital entity.
----
Another thought I just had while reading that paper is that cascading
rndomness is a reliable way of producing randomness.  Reasoning is that
a randum number string xored with a long string of one letter does not reveal
the letter. Thus, if there is a flaw in one PRNG, that flaw will be hidden in
the cascade. Probabilistically, of coruse.

Likewise, PRNGS cover each other's flaws up unless the PRNG-cascade cipher
is used to produce gigabytes of ciphertext. These are not intended for
high-volume use, they are intentionally designed to be inefficient, and
theefore not scalable.

This seems terribly obvious, once you see it, so it can't be a new thought.

Another Lebowski Enlightement. Why didn't everyone know that?

Because the NSA funds all the crypto research, and channels its
direction as it does so. A brilliant meta-psyop, much like the Fed has
done with economic research.
---------
It should be clear to most anyone I am not a cryptologer. I couldn't
beak a code to save my life, and therefore must be assumed to know nothing
about whether my creations are breakable or not.

However, the basics are simple, way down at bottom.  XOR is a
bit-level modular addition. The ultimate trap-door function.

After a modulo-operation, you can't know what numbers or symbols made up
the original 2 number, and the message can be extracted knowing or
recreating the other. OTOH, if either text or bit-string is too regular,
the other one will bleed through statistically, and that is enough to unravel
many ciphers. Thus the need for randomness in one of the bit-streams.

But if one of hte string is seriously random, nothing bleeds through.
Those are the two fundamental concepts.  All this implementation adds is
the necessity of having many different functions in each class to make
password attacks impossible. Maybe the idea of cascading randomness.
