var express=require('express'),pg=require('pg'),crypto=require('crypto'),cookieParser=require('cookie-parser'),cors=require('cors');
var app=express(),pool=new pg.Pool({connectionString:(process.env.DATABASE_URL||'').replace(/:5432/,':6543'),ssl:{rejectUnauthorized:false},max:3,idleTimeoutMillis:5000});
var FRONTEND=process.env.FRONTEND_URL||'*';
app.use(express.json({limit:'12mb'}));
app.use(cookieParser());
app.use(cors({origin:FRONTEND==='*'?true:FRONTEND,credentials:true}));
function hash(p){return crypto.createHash('sha256').update(p).digest('hex')}
function token(){return crypto.randomBytes(32).toString('hex')}

var AUTH_SQL=`
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,login TEXT UNIQUE NOT NULL,password TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT now(),avatar TEXT DEFAULT '',description TEXT DEFAULT '',banner TEXT DEFAULT '',badge TEXT DEFAULT '',views INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS posts(id SERIAL PRIMARY KEY,user_id INTEGER,category TEXT DEFAULT 'other',title TEXT DEFAULT '',content TEXT DEFAULT '',media TEXT DEFAULT '',media_type TEXT DEFAULT '',status TEXT DEFAULT 'pending',reject_reason TEXT DEFAULT '',moderator_id INTEGER,created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS admins(user_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS bans(id SERIAL PRIMARY KEY,user_id INTEGER,ip TEXT DEFAULT '',reason TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS logs(id SERIAL PRIMARY KEY,user_id INTEGER,ip TEXT DEFAULT '',device TEXT DEFAULT '',action TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS comments(id BIGSERIAL PRIMARY KEY,post_id BIGINT,user_id BIGINT,parent_id BIGINT DEFAULT 0,content TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),created_at TIMESTAMPTZ DEFAULT now());`;

pool.query(AUTH_SQL).then(function(){console.log('DB ready')}).catch(function(e){console.error('DB init error',e)});

function authMiddleware(req,res,next){
  var t=req.cookies&&req.cookies.session;
  if(!t)return res.status(401).json({error:'unauthorized'});
  pool.query('SELECT user_id FROM tokens WHERE token=$1',[t]).then(function(r){
    if(!r.rows.length)return res.status(401).json({error:'unauthorized'});
    req.userId=r.rows[0].user_id;
    next();
  }).catch(function(){res.status(500).json({error:'db error'})});
}
function optionalAuth(req,res,next){
  var t=req.cookies&&req.cookies.session;
  if(!t){req.userId=null;return next()}
  pool.query('SELECT user_id FROM tokens WHERE token=$1',[t]).then(function(r){
    req.userId=r.rows.length?r.rows[0].user_id:null;
    next();
  }).catch(function(){req.userId=null;next()});
}
function adminOnly(req,res,next){
  if(!req.userId)return res.status(401).json({error:'unauthorized'});
  pool.query('SELECT user_id FROM admins WHERE user_id=$1',[req.userId]).then(function(r){
    if(!r.rows.length)return res.status(403).json({error:'forbidden'});
    next();
  }).catch(function(){res.status(500).json({error:'db error'})});
}

app.get('/api/auth/me',authMiddleware,function(req,res){
  pool.query('SELECT id,login,avatar,description,banner FROM users WHERE id=$1',[req.userId]).then(function(r){
    if(!r.rows.length)return res.status(404).json({error:'not found'});
    var u=r.rows[0];
    pool.query('SELECT user_id FROM admins WHERE user_id=$1',[req.userId]).then(function(a){
      u.isAdmin=a.rows.length>0;
      res.json(u);
    }).catch(function(){u.isAdmin=false;res.json(u)});
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.post('/api/auth/register',function(req,res){
  var login=(req.body.login||'').trim(),pw=(req.body.password||'').trim();
  if(!login||!pw)return res.status(400).json({error:'fields required'});
  if(login.length<2||login.length>30)return res.status(400).json({error:'login 2-30 chars'});
  if(pw.length<3)return res.status(400).json({error:'password min 3'});
  pool.query('SELECT id FROM users WHERE login=$1',[login]).then(function(r){
    if(r.rows.length)return res.status(409).json({error:'login taken'});
    pool.query('INSERT INTO users(login,password) VALUES($1,$2) RETURNING id,login',[login,hash(pw)]).then(function(r){
      var u=r.rows[0],tk=token();
      pool.query('INSERT INTO tokens(token,user_id) VALUES($1,$2)',[tk,u.id]).then(function(){
        res.cookie('session',tk,{httpOnly:true,maxAge:30*24*3600*1000,sameSite:'lax'});
        u.isAdmin=false;res.json(u);
      }).catch(function(){u.isAdmin=false;res.json(u)});
    }).catch(function(){res.status(500).json({error:'db error'})});
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.post('/api/auth/login',function(req,res){
  var login=(req.body.login||'').trim(),pw=(req.body.password||'').trim();
  if(!login||!pw)return res.status(400).json({error:'fields required'});
  pool.query('SELECT id,login,password FROM users WHERE login=$1',[login]).then(function(r){
    if(!r.rows.length)return res.status(404).json({error:'not found'});
    var u=r.rows[0];
    if(u.password!==hash(pw))return res.status(401).json({error:'wrong password'});
    pool.query('SELECT id FROM bans WHERE user_id=$1',[u.id]).then(function(b){
      if(b.rows.length)return res.status(403).json({error:'banned',reason:b.rows[0].reason});
      var tk=token();
      pool.query('INSERT INTO tokens(token,user_id) VALUES($1,$2)',[tk,u.id]).then(function(){
        res.cookie('session',tk,{httpOnly:true,maxAge:30*24*3600*1000,sameSite:'lax'});
        pool.query('SELECT user_id FROM admins WHERE user_id=$1',[u.id]).then(function(a){
          res.json({id:u.id,login:u.login,isAdmin:a.rows.length>0});
        }).catch(function(){res.json({id:u.id,login:u.login})});
      }).catch(function(){res.json({id:u.id,login:u.login})});
    }).catch(function(){res.status(500).json({error:'db error'})});
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.post('/api/auth/logout',function(req,res){
  var t=req.cookies&&req.cookies.session;
  if(t)pool.query('DELETE FROM tokens WHERE token=$1',[t]).catch(function(){});
  res.clearCookie('session');
  res.json({ok:true});
});

app.get('/api/posts',optionalAuth,function(req,res){
  pool.query('SELECT id,user_id,category,title,content,status,created_at,media_type,pinned FROM posts WHERE status=$1 ORDER BY pinned DESC,created_at DESC LIMIT 50',['approved']).then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.get('/api/posts/mine',authMiddleware,function(req,res){
  pool.query('SELECT id,user_id,category,title,content,status,created_at FROM posts WHERE user_id=$1 ORDER BY created_at DESC',[req.userId]).then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.get('/api/posts/:id',optionalAuth,function(req,res){
  pool.query('SELECT * FROM posts WHERE id=$1',[req.params.id]).then(function(r){
    if(!r.rows.length)return res.status(404).json({error:'not found'});
    res.json(r.rows[0]);
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.get('/api/posts/user/:uid',optionalAuth,function(req,res){
  pool.query('SELECT id,user_id,category,title,content,status,created_at FROM posts WHERE user_id=$1 ORDER BY created_at DESC',[req.params.uid]).then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.post('/api/posts',authMiddleware,function(req,res){
  var b=req.body;
  var cat=b.category||'other',title=(b.title||'').trim(),content=(b.content||'').trim(),media=b.media||'',media_type=b.media_type||'';
  if(!title)return res.status(400).json({error:'title required'});
  var status=cat==='manual'?'approved':'pending';
  pool.query('INSERT INTO posts(user_id,category,title,content,media,media_type,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[req.userId,cat,title,content,media,media_type,status]).then(function(r){res.json(r.rows[0])}).catch(function(){res.status(500).json({error:'db error'})});
});

app.get('/api/users/search',optionalAuth,function(req,res){
  var q=req.query.q||'';
  if(!q)return res.json([]);
    pool.query("SELECT id,login,avatar,description,badge FROM users WHERE login ILIKE '%'||$1||'%' LIMIT 20",[q]).then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.get('/api/users/:id',optionalAuth,function(req,res){
  pool.query('UPDATE users SET views=views+1 WHERE id=$1',[req.params.id]).catch(function(){});
  pool.query('SELECT id,login,avatar,description,banner,badge,created_at,views FROM users WHERE id=$1',[req.params.id]).then(function(r){
    if(!r.rows.length)return res.status(404).json({error:'not found'});
    res.json(r.rows[0]);
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.patch('/api/users/:id',authMiddleware,function(req,res){
  if(parseInt(req.params.id)!==req.userId)return res.status(403).json({error:'forbidden'});
  var b=req.body,body={};
  if(b.description!==undefined)body.description=b.description;
  if(b.avatar!==undefined)body.avatar=b.avatar;
  if(b.banner!==undefined)body.banner=b.banner;
  var sets=[],vals=[req.userId],i=2;
  for(var k in body){sets.push(k+'=$'+i);vals.push(body[k]);i++}
  if(!sets.length)return res.json({ok:true});
  pool.query('UPDATE users SET '+sets.join(',')+' WHERE id=$1',vals).then(function(){res.json({ok:true})}).catch(function(e){console.error('PATCH user error',e);res.status(500).json({error:'db error'})});
});

app.get('/api/admin/pending',authMiddleware,adminOnly,function(req,res){
  pool.query('SELECT * FROM posts WHERE status=$1 ORDER BY created_at DESC',['pending']).then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.patch('/api/admin/posts/:id',authMiddleware,adminOnly,function(req,res){
  var status=req.body.status,reason=req.body.reason||'';
  pool.query('UPDATE posts SET status=$1,moderator_id=$2,reject_reason=$3 WHERE id=$4',[status,req.userId,reason,req.params.id]).then(function(){res.json({ok:true})}).catch(function(){res.status(500).json({error:'db error'})});
});

app.delete('/api/admin/posts/:id',authMiddleware,adminOnly,function(req,res){
  pool.query('DELETE FROM comments WHERE post_id=$1',[req.params.id]).then(function(){
    pool.query('DELETE FROM posts WHERE id=$1',[req.params.id]).then(function(){res.json({ok:true})}).catch(function(){res.status(500).json({error:'db error'})});
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.put('/api/admin/posts/:id/pin',authMiddleware,adminOnly,function(req,res){
  pool.query('UPDATE posts SET pinned=NOT pinned WHERE id=$1 RETURNING pinned',[req.params.id]).then(function(r){
    if(!r.rows.length)return res.status(404).json({error:'not found'});
    res.json({pinned:r.rows[0].pinned});
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.get('/api/admin/users',authMiddleware,adminOnly,function(req,res){
  pool.query('SELECT id,login,description,badge,created_at FROM users ORDER BY id').then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.get('/api/admin/users/:id/password',authMiddleware,adminOnly,function(req,res){
  pool.query('SELECT login,password FROM users WHERE id=$1',[req.params.id]).then(function(r){
    if(!r.rows.length)return res.status(404).json({error:'not found'});
    res.json(r.rows[0]);
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.post('/api/admin/admins',authMiddleware,adminOnly,function(req,res){
  pool.query('INSERT INTO admins(user_id) VALUES($1) ON CONFLICT DO NOTHING',[req.body.user_id]).then(function(){res.json({ok:true})}).catch(function(){res.status(500).json({error:'db error'})});
});

app.delete('/api/admin/admins/:uid',authMiddleware,adminOnly,function(req,res){
  pool.query('DELETE FROM admins WHERE user_id=$1',[req.params.uid]).then(function(r){res.json({ok:true,removed:r.rowCount>0})}).catch(function(){res.status(500).json({error:'db error'})});
});

app.get('/api/admin/bans',authMiddleware,adminOnly,function(req,res){
  pool.query('SELECT * FROM bans ORDER BY created_at DESC').then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.post('/api/admin/bans',authMiddleware,adminOnly,function(req,res){
  var uid=req.body.user_id,reason=req.body.reason||'';
  pool.query('SELECT user_id FROM admins WHERE user_id=$1',[uid]).then(function(r){
    if(r.rows.length)return res.status(403).json({error:'cant ban admins'});
    pool.query('INSERT INTO bans(user_id,reason) VALUES($1,$2)',[uid,reason]).then(function(){res.json({ok:true})}).catch(function(){res.status(500).json({error:'db error'})});
  }).catch(function(){res.status(500).json({error:'db error'})});
});

app.delete('/api/admin/bans/:id',authMiddleware,adminOnly,function(req,res){
  pool.query('DELETE FROM bans WHERE id=$1',[req.params.id]).then(function(){res.json({ok:true})}).catch(function(){res.status(500).json({error:'db error'})});
});

app.put('/api/admin/badge/:uid',authMiddleware,adminOnly,function(req,res){
  var badge=req.body.badge||'';
  pool.query('UPDATE users SET badge=$1 WHERE id=$2',[badge,req.params.uid]).then(function(){res.json({ok:true})}).catch(function(){res.status(500).json({error:'db error'})});
});

app.delete('/api/admin/users/:id',authMiddleware,adminOnly,function(req,res){
  var uid=parseInt(req.params.id);
  if(uid===req.userId)return res.status(400).json({error:'cant delete self'});
  Promise.all([
    pool.query('DELETE FROM posts WHERE user_id=$1',[uid]),
    pool.query('DELETE FROM bans WHERE user_id=$1',[uid]),
    pool.query('DELETE FROM logs WHERE user_id=$1',[uid]),
    pool.query('DELETE FROM comments WHERE user_id=$1',[uid]),
    pool.query('DELETE FROM admins WHERE user_id=$1',[uid]),
    pool.query('DELETE FROM tokens WHERE user_id=$1',[uid]),
    pool.query('DELETE FROM users WHERE id=$1',[uid])
  ]).then(function(){res.json({ok:true})}).catch(function(){res.status(500).json({error:'db error'})});
});

app.get('/api/admin/logs',authMiddleware,adminOnly,function(req,res){
  pool.query('SELECT * FROM logs ORDER BY created_at DESC LIMIT 100').then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.get('/api/comments/:postId',optionalAuth,function(req,res){
  pool.query('SELECT * FROM comments WHERE post_id=$1 ORDER BY created_at ASC',[req.params.postId]).then(function(r){res.json(r.rows)}).catch(function(){res.status(500).json([])});
});

app.post('/api/comments',authMiddleware,function(req,res){
  var postId=req.body.post_id,content=(req.body.content||'').trim(),parentId=req.body.parent_id||0;
  if(!postId||!content)return res.status(400).json({error:'fields required'});
  pool.query('INSERT INTO comments(post_id,user_id,parent_id,content) VALUES($1,$2,$3,$4) RETURNING *',[postId,req.userId,parentId,content]).then(function(r){res.json(r.rows[0])}).catch(function(){res.status(500).json({error:'db error'})});
});

app.post('/api/logs',authMiddleware,function(req,res){
  pool.query('INSERT INTO logs(user_id,ip,device,action) VALUES($1,$2,$3,$4)',[req.userId,req.body.ip||'0.0.0.0',req.body.device||'',req.body.action||'']).catch(function(){});
  res.json({ok:true});
});

app.get('/api/bans/check',optionalAuth,function(req,res){
  if(!req.userId)return res.json({banned:false});
  pool.query('SELECT id,reason FROM bans WHERE user_id=$1',[req.userId]).then(function(r){
    res.json({banned:r.rows.length>0,reason:r.rows.length?r.rows[0].reason:''});
  }).catch(function(){res.json({banned:false})});
});

module.exports=app;
