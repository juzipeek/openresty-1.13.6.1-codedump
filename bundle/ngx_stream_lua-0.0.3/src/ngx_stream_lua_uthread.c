
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_uthread.h"
#include "ngx_stream_lua_coroutine.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_probe.h"


#if 1
#undef ngx_stream_lua_probe_info
#define ngx_stream_lua_probe_info(msg)
#endif


static int ngx_stream_lua_uthread_spawn(lua_State *L);
static int ngx_stream_lua_uthread_wait(lua_State *L);
static int ngx_stream_lua_uthread_kill(lua_State *L);

// 注册thread相关的api
void
ngx_stream_lua_inject_uthread_api(ngx_log_t *log, lua_State *L)
{
    /* new thread table */
    lua_createtable(L, 0 /* narr */, 3 /* nrec */);

    lua_pushcfunction(L, ngx_stream_lua_uthread_spawn);
    lua_setfield(L, -2, "spawn");

    lua_pushcfunction(L, ngx_stream_lua_uthread_wait);
    lua_setfield(L, -2, "wait");

    lua_pushcfunction(L, ngx_stream_lua_uthread_kill);
    lua_setfield(L, -2, "kill");

    lua_setfield(L, -2, "thread");
}

// 创建用户线程的协程
static int
ngx_stream_lua_uthread_spawn(lua_State *L)
{
    int                           n;
    ngx_stream_lua_request_t           *r;
    ngx_stream_lua_ctx_t           *ctx;
    ngx_stream_lua_co_ctx_t        *coctx = NULL;

    // 拿到当前栈顶有多少个元素
    n = lua_gettop(L);

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    // 创建协程
    ngx_stream_lua_coroutine_create_helper(L, r, ctx, &coctx);
    // 此时栈顶是新创建的协程

    /* anchor the newly created coroutine into the Lua registry */
    // 把新创建的协程写入Lua registry表中
    // 将ngx_stream_lua_coroutines_key的地址压入栈中
    lua_pushlightuserdata(L, &ngx_stream_lua_coroutines_key);
    // 从registry表中查询该地址，registry表中该地址对应的一个数组，用于存储coroutine的
    
    lua_rawget(L, LUA_REGISTRYINDEX);

    // 此时栈顶是查询返回的值，即ngx_stream_lua_coroutines_key对应的数组
    // 栈顶-1位置是新协程
    
    // 压入协程的值
    lua_pushvalue(L, -2);
    // -2位置目前是前面那个表了，于是这里得到了这个coroutine在表中的索引值
    coctx->co_ref = luaL_ref(L, -2);

    // 栈顶位置：存储协程的表
    // 栈顶位置 - 1：协程值
    // 因此下面的操作弹出这个表
    lua_pop(L, 1);

    if (n > 1) {
        // 由于lua函数压栈顺序是从左到右
        // 因此base位置的就是压入的第一个参数，而spawn的第一个参数就是入口函数
        // 所以这里的工作，就是把线程入口函数移动到栈顶
        lua_replace(L, 1);
        // 将L栈顶的元素移动到协程中，这一步就是把除去线程入口函数的其他参数移动到新创建的协程
        lua_xmove(L, coctx->co, n - 1);
    }

    // 标记是用户线程
    coctx->is_uthread = 1;
    // 用户线程数量+1
    ctx->uthreads++;

    // 协程上下文状态切换为running
    coctx->co_status = NGX_STREAM_LUA_CO_RUNNING;
    // 保存协程op是NGX_STREAM_LUA_USER_THREAD_RESUME
    ctx->co_op = NGX_STREAM_LUA_USER_THREAD_RESUME;

    // 标记当前协程创建了用户线程才被切换执行权
    ctx->cur_co_ctx->thread_spawn_yielded = 1;

    // 将当前协程加入到posted_threads中
    if (ngx_stream_lua_post_thread(r, ctx, ctx->cur_co_ctx) != NGX_OK) {
        return luaL_error(L, "no memory");
    }

    // 保存用户线程的父协程上下文为当前协程
    coctx->parent_co_ctx = ctx->cur_co_ctx;
    // 切换当前协程为新创建的协程
    ctx->cur_co_ctx = coctx;

    ngx_stream_lua_probe_user_thread_spawn(r, L, coctx->co);

    dd("yielding with arg %s, top=%d, index-1:%s", luaL_typename(L, -1),
       (int) lua_gettop(L), luaL_typename(L, 1));
    // 将原协程的执行权切换出去，这里的参数1是新创建的协程
    // 也就是说，这里返回新创建的协程
    return lua_yield(L, 1);
}


static int
ngx_stream_lua_uthread_wait(lua_State *L)
{
    int                          i, nargs, nrets;
    lua_State                   *sub_co;
    ngx_stream_lua_request_t          *r;
    ngx_stream_lua_ctx_t          *ctx;
    ngx_stream_lua_co_ctx_t       *coctx, *sub_coctx;

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT

                               | NGX_STREAM_LUA_CONTEXT_PREREAD

                               | NGX_STREAM_LUA_CONTEXT_TIMER);

    coctx = ctx->cur_co_ctx;

    nargs = lua_gettop(L);

    for (i = 1; i <= nargs; i++) {
        // 拿到协程指针
        sub_co = lua_tothread(L, i);

        luaL_argcheck(L, sub_co, i, "lua thread expected");

        // 拿到协程上下文指针
        sub_coctx = ngx_stream_lua_get_co_ctx(sub_co, ctx);
        if (sub_coctx == NULL) {
            return luaL_error(L, "no co ctx found");
        }

        // 如果不是用户线程就返回
        if (!sub_coctx->is_uthread) {
            return luaL_error(L, "attempt to wait on a coroutine that is "
                              "not a user thread");
        }

        if (sub_coctx->parent_co_ctx != coctx) {
            return luaL_error(L, "only the parent coroutine can wait on the "
                              "thread");
        }

        switch (sub_coctx->co_status) {
        case NGX_STREAM_LUA_CO_ZOMBIE:

            ngx_stream_lua_probe_info("found zombie child");

            nrets = lua_gettop(sub_coctx->co);

            dd("child retval count: %d, %s: %s", (int) nrets,
               luaL_typename(sub_coctx->co, -1),
               lua_tostring(sub_coctx->co, -1));

            if (nrets) {
                lua_xmove(sub_coctx->co, L, nrets);
            }

#if 1
            ngx_stream_lua_del_thread(r, L, ctx, sub_coctx);
            ctx->uthreads--;
#endif

            return nrets;

        case NGX_STREAM_LUA_CO_DEAD:
            dd("uthread already waited: %p (parent %p)", sub_coctx,
               coctx);

            if (i < nargs) {
                /* just ignore it if it is not the last one */
                continue;
            }

            /* being the last one */
            lua_pushnil(L);
            lua_pushliteral(L, "already waited or killed");
            return 2;

        default:
            dd("uthread %p still alive, status: %d, parent %p", sub_coctx,
               sub_coctx->co_status, coctx);
            break;
        }

        ngx_stream_lua_probe_user_thread_wait(L, sub_coctx->co);
        sub_coctx->waited_by_parent = 1;
    }

    return lua_yield(L, 0);
}


static int
ngx_stream_lua_uthread_kill(lua_State *L)
{
    lua_State                   *sub_co;
    ngx_stream_lua_request_t          *r;
    ngx_stream_lua_ctx_t          *ctx;
    ngx_stream_lua_co_ctx_t       *coctx, *sub_coctx;

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT

                               | NGX_STREAM_LUA_CONTEXT_PREREAD

                               | NGX_STREAM_LUA_CONTEXT_TIMER);

    coctx = ctx->cur_co_ctx;

    sub_co = lua_tothread(L, 1);
    luaL_argcheck(L, sub_co, 1, "lua thread expected");

    sub_coctx = ngx_stream_lua_get_co_ctx(sub_co, ctx);

    if (sub_coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    if (!sub_coctx->is_uthread) {
        lua_pushnil(L);
        lua_pushliteral(L, "not user thread");
        return 2;
    }

    if (sub_coctx->parent_co_ctx != coctx) {
        lua_pushnil(L);
        lua_pushliteral(L, "killer not parent");
        return 2;
    }



    switch (sub_coctx->co_status) {
    case NGX_STREAM_LUA_CO_ZOMBIE:
        ngx_stream_lua_del_thread(r, L, ctx, sub_coctx);
        ctx->uthreads--;

        lua_pushnil(L);
        lua_pushliteral(L, "already terminated");
        return 2;

    case NGX_STREAM_LUA_CO_DEAD:
        lua_pushnil(L);
        lua_pushliteral(L, "already waited or killed");
        return 2;

    default:
        ngx_stream_lua_cleanup_pending_operation(sub_coctx);
        ngx_stream_lua_del_thread(r, L, ctx, sub_coctx);
        ctx->uthreads--;

        lua_pushinteger(L, 1);
        return 1;
    }

    /* not reacheable */
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
