%%%-------------------------------------------------------------------
%%% File    : epam.erl
%%% Author  : Evgeniy Khramtsov <xram@jabber.ru>
%%% Purpose : PAM authentication and accounting management
%%% Created : 5 Jul 2007 by Evgeniy Khramtsov <xram@jabber.ru>
%%%
%%%
%%% Copyright (C) 2002-2021 ProcessOne, SARL. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------

-module(epam).

-author('ekhramtsov@process-one.net').

-behaviour(gen_server).

-include_lib("kernel/include/file.hrl").

%% API
-export([start_link/0, start/0, stop/0]).

-export([authenticate/3, authenticate/4, acct_mgmt/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
	 handle_info/2, terminate/2, code_change/3]).

-define(WARNING,
	"File ~p is world-wide executable. This "
        "is a possible security hole in your "
        "system. This file must be setted root "
        "on execution and only erlang user must "
        "be able to read/execute it. You have "
        "been warned :)~n").

-define(PROCNAME, ?MODULE).

-define(CMD_AUTH, 0).
-define(CMD_ACCT, 1).

-record(state, {port}).

start() ->
    ChildSpec = {?PROCNAME, {?MODULE, start_link, []},
		 transient, 1000, worker, [?MODULE]},
    supervisor:start_child(epam_sup, ChildSpec).

stop() ->
    gen_server:call(?PROCNAME, stop),
    supervisor:terminate_child(epam_sup, ?PROCNAME),
    supervisor:delete_child(epam_sup, ?PROCNAME).

start_link() ->
    gen_server:start_link({local, ?PROCNAME}, ?MODULE, [],
			  []).

authenticate(Srv, User, Pass)
    when is_binary(Srv), is_binary(User), is_binary(Pass) ->
    gen_server:call(?PROCNAME,
		    {authenticate, Srv, User, Pass, <<"">>}).

authenticate(Srv, User, Pass, Rhost)
    when is_binary(Srv), is_binary(User), is_binary(Pass), is_binary(Rhost) ->
    gen_server:call(?PROCNAME,
		    {authenticate, Srv, User, Pass, Rhost}).

acct_mgmt(Srv, User)
    when is_binary(Srv), is_binary(User) ->
    gen_server:call(?PROCNAME, {acct_mgmt, Srv, User}).

init([]) ->
    FileName = filename:join(get_bin_path(), "epam"),
    case file:read_file_info(FileName) of
      {ok, Info} ->
	  Mode = Info#file_info.mode band 2049,
	  if Mode == 2049 ->
                  error_logger:error_msg(?WARNING, [FileName]);
	     true -> ok
	  end,
	  Port = open_port({spawn, FileName},
			   [{packet, 2}, binary, exit_status]),
	  {ok, #state{port = Port}};
      {error, Reason} ->
            error_logger:error_msg("Can't open file ~p: ~p~n",
                                   [FileName, Reason]),
	  error
    end.

terminate(_Reason, #state{port = Port}) ->
    catch port_close(Port), ok.

handle_call({authenticate, Srv, User, Pass, Rhost}, From,
	    State) ->
    Port = State#state.port,
    FromBin = term_to_binary(From),
    Data = <<?CMD_AUTH:8, (size(FromBin)):16/integer-big, FromBin/binary, 0:8,
	     (size(Srv)):16/integer-big, Srv/binary, 0:8, (size(User)):16/integer-big, User/binary, 0:8,
	     (size(Pass)):16/integer-big, Pass/binary, 0:8, (size(Rhost)):16/integer-big, Rhost/binary, 0:8>>,
    port_command(Port, Data),
    {noreply, State};
handle_call({acct_mgmt, Srv, User}, From, State) ->
    Port = State#state.port,
    FromBin = term_to_binary(From),
    Data = <<?CMD_ACCT:8, (size(FromBin)):16/integer-big, FromBin/binary, 0:8,
	     (size(Srv)):16/integer-big, Srv/binary, 0:8, (size(User)):16/integer-big, User/binary, 0:8>>,
    port_command(Port, Data),
    {noreply, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    {reply, bad_request, State}.

handle_info({Port, {data, Data}},
	    #state{port = Port} = State) ->
    case Data of
	<<1:8, PidLen:16/integer-big, Pid:PidLen/binary>> ->
	    gen_server:reply(binary_to_term(Pid), true);
	<<0:8, PidLen:16/integer-big, Pid:PidLen/binary, ErrLen:16/integer-big, ErrTxt:ErrLen/binary>> ->
	    gen_server:reply(binary_to_term(Pid), {false, ErrTxt});
	Err ->
	    error_logger:error_msg("Got invalid reply from ~p: ~p~n", [Port, Err])
    end,
    {noreply, State};
handle_info({Port, {exit_status, _}},
	    #state{port = Port} = State) ->
    {stop, port_died, State};
handle_info(Msg, State) ->
    error_logger:error_msg("got unexpected message: ~p~n", [Msg]),
    {noreply, State}.

handle_cast(_Msg, State) -> {noreply, State}.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

get_bin_path() ->
    case code:priv_dir(epam) of
	{error, _} ->
	    EbinDir = filename:dirname(code:which(epam)),
	    AppDir = filename:dirname(EbinDir),
	    filename:join([AppDir, "priv", "bin"]);
	Path ->
	    filename:join([Path, "bin"])
    end.
