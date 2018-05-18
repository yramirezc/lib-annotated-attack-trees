:- [guaranteesKb].
guaranteed(Id,[A,V,C]) :- allowedAction(Id, [X,W,Y]), actionsMatch([A,V,C],[X,W,Y]).
actionsMatch([A,V,C],[X,V,Y]) :- setMatch(A,X), setMatch(C,Y).
setMatch(A,B) :- subset(A,B), subset(B,A).





