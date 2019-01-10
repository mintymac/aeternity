-module(aestratum_jsonrpc_utils).

-include("aestratum_jsonrpc.hrl").

-export([next_id/1,
         to_id/1
        ]).

next_id(Id) when is_integer(Id) ->
    (Id + 1) band ?ID_MAX.

to_id(Id) when ?IS_ID(Id) ->
    Id;
to_id(_Other) ->
    null.

