
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_coroutine.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_probe.h"


/*
 * Design:
 *
 * In order to support using ngx.* API in Lua coroutines, we have to create
 * new coroutine in the main coroutine instead of the calling coroutine
 */


static int ngx_stream_lua_coroutine_create(lua_State *L);
static int ngx_stream_lua_coroutine_resume(lua_State *L);
static int ngx_stream_lua_coroutine_yield(lua_State *L);
static int ngx_stream_lua_coroutine_status(lua_State *L);


static const ngx_str_t
    ngx_stream_lua_co_status_names[] =
    {
        ngx_string("running"),
        ngx_string("suspended"),
        ngx_string("normal"),
        ngx_string("dead"),
        ngx_string("zombie")
    };


// 新的coroutine的create函数
static int
ngx_stream_lua_coroutine_create(lua_State *L)
{
    ngx_stream_lua_request_t          *r;
    ngx_stream_lua_ctx_t          *ctx;

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    return ngx_stream_lua_coroutine_create_helper(L, r, ctx, NULL);
}

// 创建协程的辅助函数
// 注意传入的参数L，是父协程
// 完毕之后，新创建的协程在栈顶
int
ngx_stream_lua_coroutine_create_helper(lua_State *L, ngx_stream_lua_request_t *r,
    ngx_stream_lua_ctx_t *ctx, ngx_stream_lua_co_ctx_t **pcoctx)
{
    lua_State                     *vm;  /* the Lua VM */
    lua_State                     *co;  /* new coroutine to be created */
    ngx_stream_lua_co_ctx_t         *coctx; /* co ctx for the new coroutine */

    luaL_argcheck(L, lua_isfunction(L, 1) && !lua_iscfunction(L, 1), 1,
                  "Lua function expected");

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT
                               | NGX_STREAM_LUA_CONTEXT_TIMER
                               | NGX_STREAM_LUA_CONTEXT_PREREAD
        );

    // 拿到进程的Lua虚拟机
    vm = ngx_stream_lua_get_lua_vm(r, ctx);

    /* create new coroutine on root Lua state, so it always yields
     * to main Lua thread
     */
    // 使用进程的Lua虚拟机创建出来一个协程
    co = lua_newthread(vm);

    ngx_stream_lua_probe_user_coroutine_create(r, L, co);

    // 查询ngx_stream_lua_co_ctx_t
    coctx = ngx_stream_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        coctx = ngx_stream_lua_create_co_ctx(r, ctx);
        if (coctx == NULL) {
            return luaL_error(L, "no memory");
        }

    } else {
        ngx_memzero(coctx, sizeof(ngx_stream_lua_co_ctx_t));
        coctx->co_ref = LUA_NOREF;
    }

    coctx->co = co;
    // 初始化的状态是suspend
    coctx->co_status = NGX_STREAM_LUA_CO_SUSPENDED;

    /* make new coroutine share globals of the parent coroutine.
     * NOTE: globals don't have to be separated! */
    // 拿到父协程的全局表
    ngx_stream_lua_get_globals_table(L);
    // 移动到新创建的协程co中
    lua_xmove(L, co, 1);
    // 写入新协程的全局表
    ngx_stream_lua_set_globals_table(co);

    // 将新创建的协程从进程虚拟机，移动到父协程中
    lua_xmove(vm, L, 1);    /* move coroutine from main thread to L */

    // 将父协程L的入口函数压入栈中
    lua_pushvalue(L, 1);    /* copy entry function to top of L*/
    // 移动到新创建的协程中
    lua_xmove(L, co, 1);    /* move entry function from L to co */

    if (pcoctx) {
        *pcoctx = coctx;
    }

#ifdef NGX_LUA_USE_ASSERT
    coctx->co_top = 1;
#endif

    return 1;    /* return new coroutine to Lua */
}


// 新的coroutine的resume函数
static int
ngx_stream_lua_coroutine_resume(lua_State *L)
{
    lua_State                   *co;
    ngx_stream_lua_request_t          *r;
    ngx_stream_lua_ctx_t          *ctx;
    ngx_stream_lua_co_ctx_t       *coctx;
    ngx_stream_lua_co_ctx_t       *p_coctx; /* parent co ctx */

    co = lua_tothread(L, 1);

    luaL_argcheck(L, co, 1, "coroutine expected");

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT
                               | NGX_STREAM_LUA_CONTEXT_TIMER
                               | NGX_STREAM_LUA_CONTEXT_PREREAD
        );

    // 拿到当前协程上下文的指针做为父指针
    p_coctx = ctx->cur_co_ctx;
    if (p_coctx == NULL) {  // 为空则返回
        return luaL_error(L, "no parent co ctx found");
    }

    // 拿到待resume协程的ngx_stream_lua_co_ctx_t指针
    coctx = ngx_stream_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    ngx_stream_lua_probe_user_coroutine_resume(r, L, co);

    // 检查状态
    if (coctx->co_status != NGX_STREAM_LUA_CO_SUSPENDED) {
        dd("coroutine resume: %d", coctx->co_status);

        lua_pushboolean(L, 0);
        lua_pushfstring(L, "cannot resume %s coroutine",
                        ngx_stream_lua_co_status_names[coctx->co_status].data);
        return 2;
    }

    // 当前协程状态修改为normal
    p_coctx->co_status = NGX_STREAM_LUA_CO_NORMAL;

    // 待resume协程的父协程上下文修改为当前协程
    coctx->parent_co_ctx = p_coctx;

    dd("set coroutine to running");
    // 待resume协程状态修改为running
    coctx->co_status = NGX_STREAM_LUA_CO_RUNNING;

    // 修改op操作为NGX_STREAM_LUA_USER_CORO_RESUME
    ctx->co_op = NGX_STREAM_LUA_USER_CORO_RESUME;
    // 修改当前协程上下文指针
    ctx->cur_co_ctx = coctx;

    /* yield and pass args to main thread, and resume target coroutine from
     * there */
    return lua_yield(L, lua_gettop(L) - 1);
}

// 新的coroutine的yield函数
static int
ngx_stream_lua_coroutine_yield(lua_State *L)
{
    ngx_stream_lua_request_t          *r;
    ngx_stream_lua_ctx_t          *ctx;
    ngx_stream_lua_co_ctx_t       *coctx;

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT
                               | NGX_STREAM_LUA_CONTEXT_TIMER
                               | NGX_STREAM_LUA_CONTEXT_PREREAD
        );

    coctx = ctx->cur_co_ctx;

    coctx->co_status = NGX_STREAM_LUA_CO_SUSPENDED;

    ctx->co_op = NGX_STREAM_LUA_USER_CORO_YIELD;

    if (!coctx->is_uthread && coctx->parent_co_ctx) {
        dd("set coroutine to running");
        coctx->parent_co_ctx->co_status = NGX_STREAM_LUA_CO_RUNNING;

        ngx_stream_lua_probe_user_coroutine_yield(r, coctx->parent_co_ctx->co, L);

    } else {
        ngx_stream_lua_probe_user_coroutine_yield(r, NULL, L);
    }

    /* yield and pass retvals to main thread,
     * and resume parent coroutine there */
    return lua_yield(L, lua_gettop(L));
}

// 这里注册新的coroutine函数到lua中
void
ngx_stream_lua_inject_coroutine_api(ngx_log_t *log, lua_State *L)
{
    int         rc;

    /* new coroutine table */
    // 创建一个空表
    lua_createtable(L, 0 /* narr */, 14 /* nrec */);

    /* get old coroutine table */
    // 拿到全局表中的coroutine表
    lua_getglobal(L, "coroutine");

    /* set running to the old one */
    // 以下将原先coroutine相关的几个成员，分别设置到新的空表中
    // old running -> new running
    lua_getfield(L, -1, "running");
    lua_setfield(L, -3, "running");

    // old create -> new _create
    lua_getfield(L, -1, "create");
    lua_setfield(L, -3, "_create");

    // old resume -> new _resume
    lua_getfield(L, -1, "resume");
    lua_setfield(L, -3, "_resume");

    // old yield -> new _yield
    lua_getfield(L, -1, "yield");
    lua_setfield(L, -3, "_yield");

    // old status -> new _status
    lua_getfield(L, -1, "status");
    lua_setfield(L, -3, "_status");

    /* pop the old coroutine */
    // 弹出旧的coroutine库
    lua_pop(L, 1);

    // 设置新的create、resume、yield、status函数到对应的”__函数名“
    lua_pushcfunction(L, ngx_stream_lua_coroutine_create);
    lua_setfield(L, -2, "__create");

    lua_pushcfunction(L, ngx_stream_lua_coroutine_resume);
    lua_setfield(L, -2, "__resume");

    lua_pushcfunction(L, ngx_stream_lua_coroutine_yield);
    lua_setfield(L, -2, "__yield");

    lua_pushcfunction(L, ngx_stream_lua_coroutine_status);
    lua_setfield(L, -2, "__status");

    // OK，存入最新的coroutine表
    lua_setglobal(L, "coroutine");

    // 执行一段Lua代码插入新的coroutine函数API
    /* inject coroutine APIs */
    {
        const char buf[] =
            "local keys = {'create', 'yield', 'resume', 'status'}\n"
            "local getfenv = getfenv\n"
            "for _, key in ipairs(keys) do\n"
               "local std = coroutine['_' .. key]\n"
               "local ours = coroutine['__' .. key]\n"
               "local raw_ctx = ngx._phase_ctx\n"
               "coroutine[key] = function (...)\n"
                    "local r = getfenv(0).__ngx_req\n"
                    "if r then\n"
                        "local ctx = raw_ctx(r)\n"
                        /* ignore header and body filters */
                        "if ctx ~= 0x020 and ctx ~= 0x040 then\n"
                            "return ours(...)\n"
                        "end\n"
                    "end\n"
                    "return std(...)\n"
                "end\n"
            "end\n"
            "local create, resume = coroutine.create, coroutine.resume\n"
            "coroutine.wrap = function(f)\n"
               "local co = create(f)\n"
               "return function(...) return select(2, resume(co, ...)) end\n"
            "end\n"
            "package.loaded.coroutine = coroutine";

#if 0
            "debug.sethook(function () collectgarbage() end, 'rl', 1)"
#endif
            ;

        rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "=coroutine.wrap");
    }

    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "failed to load Lua code for coroutine.wrap(): %i: %s",
                      rc, lua_tostring(L, -1));

        lua_pop(L, 1);
        return;
    }

    rc = lua_pcall(L, 0, 0, 0);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "failed to run the Lua code for coroutine.wrap(): %i: %s",
                      rc, lua_tostring(L, -1));
        lua_pop(L, 1);
    }
}

// 新的coroutine的status函数
static int
ngx_stream_lua_coroutine_status(lua_State *L)
{
    lua_State                     *co;  /* new coroutine to be created */
    ngx_stream_lua_request_t            *r;
    ngx_stream_lua_ctx_t            *ctx;
    ngx_stream_lua_co_ctx_t         *coctx; /* co ctx for the new coroutine */

    co = lua_tothread(L, 1);

    luaL_argcheck(L, co, 1, "coroutine expected");

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT
                               | NGX_STREAM_LUA_CONTEXT_TIMER
                               | NGX_STREAM_LUA_CONTEXT_PREREAD
        );

    coctx = ngx_stream_lua_get_co_ctx(co, ctx);
    if (coctx == NULL) {
        lua_pushlstring(L, (const char *)
                        ngx_stream_lua_co_status_names[NGX_STREAM_LUA_CO_DEAD].data,
                        ngx_stream_lua_co_status_names[NGX_STREAM_LUA_CO_DEAD].len);
        return 1;
    }

    dd("co status: %d", coctx->co_status);

    lua_pushlstring(L, (const char *)
                    ngx_stream_lua_co_status_names[coctx->co_status].data,
                    ngx_stream_lua_co_status_names[coctx->co_status].len);
    return 1;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
