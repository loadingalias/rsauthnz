---------------------------- MODULE AuthorityInd ----------------------------
EXTENDS AuthorityInvariant

\* Fixed proof constants are expanded before symbolic state construction.
\* Origin still ranges over both initial states through CInit.
OVERRIDE_Bad == "none"
OVERRIDE_Turn == "creation"
OVERRIDE_Raise == "none"
=============================================================================
