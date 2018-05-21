:- [guaranteesKb].
:- [assumptionsKb].

/**
 * Manually defined rules relating to guarantees
 */

guaranteed(CVE,[A,V,C]) :- allowedAction(CVE, [X,W,Y]), actionsMatch([A,V,C],[X,W,Y]).
actionsMatch([A,V,C],[X,V,Y]) :- setMatch(A,X), setMatch(C,Y).
setMatch(A,B) :- subset(A,B), subset(B,A).

/**
 * Manually defined rules relating to assumptions
 */

envPropertyAlsoMatches(CVE,X) :- envPropertyMatches(CVE,Y), runsOn(Z,X), isSubdescription(Z,Y).
isSubdescription([X|T],[X,T]) :- !.
isSubdescription([X|T],[X|T1]) :- isSubdescr(T,T1).
isSubdescr([X],[X|_]).

envAllowingAction(X,Y) :- envPropertyMatches(CVE,X), allowedAction(CVE,Y).
manAllowingAction(X,Y) :- envPropertyMatches(CVE,[X|_]), allowedAction(CVE,Y).
manSimultaneouslyAllowing(A1,A2,Inter) :- setof(X,manAllowingAction(X,A1),S1), setof(Y,manAllowingAction(Y,A2),S2), intersection(S1,S2,Inter).

% Testing

envPropertyMustMatch([microsoft,windows]).

/**
 * Manually defined facts relating to assumptions
 */

runsOn([microsoft,word],[microsoft,windows]).
runsOn([microsoft,windows_media_player],[microsoft,windows]).
runsOn([apple,itunes],[apple,mac_os]).

/**
 * Manually defined facts relating to guarantees
 */

