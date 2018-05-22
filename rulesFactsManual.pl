:- [guaranteesKbAuto].
:- [assumptionsKbAuto].

/**
 * Implementation of the attachable predicate
 */

attachable(CVE,A,G) :- nonContradictory(CVE,A), guaranteesSome(CVE,G).
nonContradictory(_,acceptAll) :- !.
nonContradictory(CVE,[A1|_]) :- envPropertyMatches(CVE,X), isSubdescription(A1,X).
nonContradictory(CVE,[_|RA]) :- nonContradictory(CVE,RA).
nonContradictory(CVE,A) :- envPropertyAlsoMatches(CVE,X), member(Y,A), isSubdescription(Y,X).
guaranteesSome(CVE,G) :- member(X,G), guaranteed(CVE,X).

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

isSubdescription([X|T],[X|T]) :- !.
isSubdescription([X|T],[X|T1]) :- isSubdescription(T,T1).
isSubdescription([],[_|_]) :- !.
isSubdescription([],[]) :- !.

envAllowingAction(X,Y) :- envPropertyMatches(CVE,X), allowedAction(CVE,Y).
manufacturerAllowingAction(X,Y) :- envPropertyMatches(CVE,[X|_]), allowedAction(CVE,Y).
manufSimultaneouslyAllowing(A1,A2,Inter) :- setof(X,manufacturerAllowingAction(X,A1),S1), setof(Y,manufacturerAllowingAction(Y,A2),S2), intersection(S1,S2,Inter).
productAllowingAction([X,Y],Z) :- envPropertyMatches(CVE,[X,Y|_]), allowedAction(CVE,Z).
productSimultaneouslyAllowing(A1,A2,Inter) :- setof(X,productAllowingAction(X,A1),S1), setof(Y,productAllowingAction(Y,A2),S2), intersection(S1,S2,Inter).

countAttachable(A,G,L) :- setof(X,attachable(X,A,G),S), length(S,L).

/**
 * Manually defined facts relating to assumptions (for the moment, this is here only to serve as an example)
 */

runsOn([microsoft,word],[microsoft,windows]).
runsOn([microsoft,windows_media_player],[microsoft,windows]).
runsOn([apple,itunes],[apple,mac_os]).

/**
 * Manually defined facts relating to guarantees
 */

