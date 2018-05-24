:- [guaranteesKbAuto].
:- [assumptionsKbAuto].

/**
 * Implementation of the attachable predicate
 */

attachable(CVE,A,G) :- nonContradictingPlatformAssumptions(CVE,A), allActionsGuaranteed(CVE,G).

nonContradictingPlatformAssumptions(_,attachAnything) :- !.
nonContradictingPlatformAssumptions(CVE,assumedPlatforms(P)) :- nonContradicting(CVE,P).
nonContradicting(CVE,[A1|_]) :- affectedPlatform(CVE,X), isSubdescription(A1,X); indirectlyAffectedPlatform(CVE,X), isSubdescription(A1,X).
nonContradicting(CVE,[_|RA]) :- nonContradicting(CVE,RA).
indirectlyAffectedPlatform(CVE,X) :- affectedPlatform(CVE,Y), runsOn(Z,X), isSubdescription(Z,Y).
isSubdescription([X|T],[X|T]) :- !.
isSubdescription([X|T],[X|T1]) :- isSubdescription(T,T1).
isSubdescription([],[_|_]) :- !.
isSubdescription([],[]) :- !.

allActionsGuaranteed(_,everythingGuaranteed) :- !.
allActionsGuaranteed(CVE,requiredActions(A)) :- actionsGuaranteed(CVE,A).
actionsGuaranteed(_,[]) :- !.
actionsGuaranteed(CVE,[X|L]) :- guaranteed(CVE,X), actionsGuaranteed(CVE,L).
guaranteed(CVE,[A,V,C]) :- allowedAction(CVE, [X,W,Y]), actionsMatch([A,V,C],[X,W,Y]).
actionsMatch([A,V,C],[X,V,Y]) :- setMatch(A,X), setMatch(C,Y).
setMatch(A,B) :- subset(A,B), subset(B,A).

/**
 * Support, bookkeeping and tests
 */
 
envAllowingAction(X,Y) :- affectedPlatform(CVE,X), allowedAction(CVE,Y).
manufacturerAllowingAction(X,Y) :- affectedPlatform(CVE,[X|_]), allowedAction(CVE,Y).
manufSimultaneouslyAllowing(A1,A2,Inter) :- setof(X,manufacturerAllowingAction(X,A1),S1), setof(Y,manufacturerAllowingAction(Y,A2),S2), intersection(S1,S2,Inter).
productAllowingAction([X,Y],Z) :- affectedPlatform(CVE,[X,Y|_]), allowedAction(CVE,Z).
productSimultaneouslyAllowing(A1,A2,Inter) :- setof(X,productAllowingAction(X,A1),S1), setof(Y,productAllowingAction(Y,A2),S2), intersection(S1,S2,Inter).

countAttachable(A,G,L) :- setof(X,attachable(X,A,G),S), length(S,L).

/**
 * Manually defined facts to support additional inference on assumptions (for the moment, this is here only to serve as an example of what can be added in a real-world setting)
 */

runsOn([microsoft,word],[microsoft,windows]).
runsOn([microsoft,windows_media_player],[microsoft,windows]).
runsOn([apple,itunes],[apple,mac_os]).

/**
 * Manually defined facts to support additional inference on guarantees (no examples for the moment)
 */

