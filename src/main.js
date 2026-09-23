const Koa=require('koa'); const app=new Koa(); app.use(ctx=>{if(ctx.path==='/health') ctx.body={status:'ok'}; else ctx.status=404}); app.listen(process.env.PORT||3000,process.env.HOST||'0.0.0.0');

