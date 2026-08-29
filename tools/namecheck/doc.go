/*
Command namecheck is the gate that stops the case-insensitive name work from
coming back.

It exists because of a specific, repeated failure. Over six stages of converting
tdns to fold DNS names by the DNS rule, four defects had the same shape: TWO
SIDES OF A PAIR FOLDED BY DIFFERENT FUNCTIONS.

  - a "_dns." prefix TEST folded, the STRIP beside it not
  - a ZONEMD digest's ORDERING folded, its HASHING not
  - a map's LOOKUP folded, the STORE not
  - a duplicate-zone key folded one way, the registry another

A grep for bad calls would have caught NONE of them. In every case the call a
grep would flag had already been converted; what was left was a second, uncoerced
half elsewhere. So this is a parser, not a grep -- which also means it is not
fooled by a block comment, as the ad-hoc scan that drove those six stages was --
it filtered line comments and knew nothing about the other kind. Two
of the "sites" that scan reported turned out to be commented-out code.

Three checks:

	keyfold   A map key must not be built by a fold that is lossy. dns.CanonicalName
	          folds case correctly but rewrites any octet that is not valid UTF-8
	          into U+FFFD, so two distinct names collide on one key;
	          strings.ToLower folds by Unicode, so U+212A KELVIN SIGN and "k"
	          collide too. Keys use core.CanonicalizeName.

	namecmp   A domain name must not be compared with strings.EqualFold (Unicode,
	          not RFC 4343) or with a byte-wise suffix test (blind to label
	          boundaries: "ns.evilexample." ends with "example.").

	foldpair  Within one function, a value tested through a fold and then used
	          unfolded -- HasPrefix(fold(s), lit) beside TrimPrefix(s, lit) -- is
	          the "_dns." bug exactly.

Usage:

	namecheck [-allow FILE] DIR...

Exit status is 1 if anything is reported. An allowlist file carries one
"path:line: reason" per line for the sites that are deliberate; a reason is
required, so an entry has to say why.
*/
package main
