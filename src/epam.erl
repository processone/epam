%%%-------------------------------------------------------------------
%%% File    : epam.erl
%%% Author  : Evgeniy Khramtsov <xram@jabber.ru>
%%% Purpose : PAM authentication and accounting management
%%% Created : 5 Jul 2007 by Evgeniy Khramtsov <xram@jabber.ru>
%%%
%%%
%%% epam, Copyright (C) 2002-2013   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%-------------------------------------------------------------------

-module(epam).

-author('ekhramtsov@process-one.net').

-behaviour(gen_server).

-include_lib("kernel/include/file.hrl").

%% API
-export([start_link/0, start/0, stop/0]).

-export([authenticate/3, acct_mgmt/2]).

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
		    {authenticate, Srv, User, Pass}).

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

handle_call({authenticate, Srv, User, Pass}, From,
	    State) ->
    Port = State#state.port,
    Data = term_to_binary({?CMD_AUTH, From,
			   {Srv, User, Pass}}),
    port_command(Port, Data),
    {noreply, State};
handle_call({acct_mgmt, Srv, User}, From, State) ->
    Port = State#state.port,
    Data = term_to_binary({?CMD_ACCT, From, {Srv, User}}),
    port_command(Port, Data),
    {noreply, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    {reply, bad_request, State}.

handle_info({Port, {data, Data}},
	    #state{port = Port} = State) ->
    case binary_to_term(Data) of
      {Cmd, To, Reply}
	  when Cmd == (?CMD_AUTH); Cmd == (?CMD_ACCT) ->
	  gen_server:reply(To, Reply);
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
    case os:getenv("EJABBERD_BIN_PATH") of
	false ->
	    case code:priv_dir(p1_pam) of
		{error, _} ->
                    filename:join(["priv", "bin"]);
		Path ->
		    filename:join([Path, "bin"])
	    end;
	Path ->
	    Path
    end.
