:- [guaranteesKb].
:- [assumptionsKb].

/**
 * Manually defined facts and rules relating to guarantees
 */

guaranteed(CVE,[A,V,C]) :- allowedAction(CVE, [X,W,Y]), actionsMatch([A,V,C],[X,W,Y]).
actionsMatch([A,V,C],[X,V,Y]) :- setMatch(A,X), setMatch(C,Y).
setMatch(A,B) :- subset(A,B), subset(B,A).

/**
 * Manually defined facts and rules relating to assumptions
 */

runsOn([microsoft,word],[microsoft,windows]).
runsOn([microsoft,windows_media_player],[microsoft,windows]).
runsOn([apple,itunes],[apple,mac_os]).

envPropertyAlsoMatches(CVE,X) :- envPropertyMatches(CVE,Y), runsOn(Z,X), isSubdescription(Z,Y).
isSubdescription([X|T],[X,T]) :- !.
isSubdescription([X|T],[X|T1]) :- isSubdescr(T,T1).
isSubdescr([X],[X|_]).




