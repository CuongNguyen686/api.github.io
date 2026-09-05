const express=require("express");
const cors=require("cors");
const dotenv=require("dotenv");
const crypto=require("crypto");
const jwt=require("jsonwebtoken");
const admin=require("firebase-admin");
dotenv.config();

const app=express();
app.use(cors({origin:process.env.CORS_ORIGIN||true}));
app.use(express.json({limit:"1mb"}));

if(!admin.apps.length){
  if(process.env.FIREBASE_SERVICE_ACCOUNT_JSON){
    admin.initializeApp({credential:admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)),databaseURL:process.env.FIREBASE_DATABASE_URL});
  }else{
    admin.initializeApp({credential:admin.credential.applicationDefault(),databaseURL:process.env.FIREBASE_DATABASE_URL});
  }
}
const db=admin.database();
const JWT_SECRET=process.env.JWT_SECRET||"change-this-secret";

function auth(req,res,next){
  try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))throw 0;req.admin=jwt.verify(h.slice(7),JWT_SECRET);next()}
  catch(e){res.status(401).json({error:"Unauthorized"})}
}
function randomChars(n){
 const sets={upper:"ABCDEFGHIJKLMNOPQRSTUVWXYZ",lower:"abcdefghijklmnopqrstuvwxyz",digit:"0123456789",underscore:"_"};
 const all=sets.upper+sets.lower+sets.digit+sets.underscore;
 if(n<4)throw new Error("Token length must be >= 4");
 let out=sets.upper[crypto.randomInt(sets.upper.length)]+sets.lower[crypto.randomInt(sets.lower.length)]+sets.digit[crypto.randomInt(sets.digit.length)]+sets.underscore;
 while(out.length<n)out+=all[crypto.randomInt(all.length)];
 return out.split("").sort(()=>crypto.randomInt(3)-1).join("");
}
function hash(s){return crypto.createHash("sha256").update(s).digest("hex")}
function shortRandom(){return randomChars(10)}
function render(t,v){
 return String(t||"").replace(/\{(\w+)\}/g,(_,k)=>v[k]??"");
}
function normalizePackage(x,id){
 return {...x,id,tokenPreview:x.tokenPreview||"pkg_••••••••",active:x.active!==false};
}

app.get("/health",(req,res)=>res.json({ok:true}));
app.post("/api/admin/login",(req,res)=>{
 const secret=req.body?.adminSecret;
 const adminSecret=process.env.ADMIN_LOGIN_SECRET||"nguyencuongios";
 if(!secret||secret!==adminSecret)return res.status(401).json({error:"Invalid admin secret"});
 const token=jwt.sign({role:"admin"},JWT_SECRET,{expiresIn:"12h"});
 res.json({token});
});

app.get("/api/admin/packages",auth,async(req,res)=>{
 const snap=await db.ref("packages").once("value");const v=snap.val()||{};
 res.json({packages:Object.entries(v).map(([id,x])=>normalizePackage(x,id))});
});

app.post("/api/admin/packages",auth,async(req,res)=>{
 const b=req.body||{};
 if(!b.name||!b.packageId) return res.status(400).json({error:"name and packageId required"});
 if(!/^[a-zA-Z0-9_-]+$/.test(b.packageId))return res.status(400).json({error:"Invalid packageId"});
 const tokenLength=Math.max(4,Math.min(256,Number(b.tokenLength)||64));
 const id=b.packageId;
 const ref=db.ref("packages/"+id);const old=(await ref.once("value")).val();
 if(old)return res.status(409).json({error:"Package ID already exists"});
 const rawToken=(b.tokenPrefix||"pkg_")+randomChars(tokenLength);
 const data={name:b.name,packageId:id,packageTokenHash:hash(rawToken),tokenPrefix:b.tokenPrefix||"pkg_",tokenLength,keyNameTemplate:b.keyNameTemplate||"{package}_{user}_{random}",defaultExpirationDays:Number(b.defaultExpirationDays)||0,defaultRateLimit:Number(b.defaultRateLimit)||0,allowCustomKeyName:b.allowCustomKeyName!==false,messageTemplate:b.messageTemplate||"",active:true,createdAt:Date.now()};
 await ref.set(data);
 res.json({id,packageToken:rawToken,warning:"Package token is shown once. Store it securely."});
});

app.delete("/api/admin/packages/:id",auth,async(req,res)=>{
 const id=req.params.id;const ks=(await db.ref("apiKeys").once("value")).val()||{};
 if(Object.values(ks).some(k=>k.packageId===id&&k.status==="active"))return res.status(409).json({error:"Package has active keys"});
 await db.ref("packages/"+id).remove();res.json({ok:true});
});

app.get("/api/admin/keys",auth,async(req,res)=>{
 const [ks,ps]=await Promise.all([db.ref("apiKeys").once("value"),db.ref("packages").once("value")]);
 const p=ps.val()||{};const k=ks.val()||{};
 res.json({keys:Object.entries(k).map(([id,x])=>({...x,id,packageName:p[x.packageId]?.name||x.packageId}))});
});

app.post("/api/admin/keys",auth,async(req,res)=>{
 const b=req.body||{};const p=(await db.ref("packages/"+b.packageId).once("value")).val();
 if(!p||p.active===false)return res.status(400).json({error:"Invalid package"});
 if(!b.userId&&!b.username)return res.status(400).json({error:"userId or username required"});
 let keyName=b.keyName||"";
 if(!p.allowCustomKeyName||!keyName)keyName=render(p.keyNameTemplate,{package:p.name,user:b.username||b.userId,device:b.device||"",random:shortRandom()});
 const body=randomChars(Math.max(32,Number(p.tokenLength)||64));
 const secret=(p.tokenPrefix||"key_")+body;
 const id=crypto.randomUUID();
 const data={packageId:b.packageId,keyName,keyHash:hash(secret),keyPreview:secret.slice(0,Math.min(12,secret.length))+"••••",status:b.status==="disabled"?"disabled":"active",userId:b.userId||"",username:b.username||"",email:b.email||"",device:b.device||"",note:b.note||"",customFields:b.customFields||{},rateLimit:Number(b.rateLimit)||Number(p.defaultRateLimit)||0,expiresAt:b.expiresAt||null,createdAt:Date.now(),lastUsedAt:null,requestCount:0};
 await db.ref("apiKeys/"+id).set(data);
 const message=render(p.messageTemplate,{user:b.username||b.userId,package:p.name,keyName,key:secret,expiresAt:b.expiresAt||"Never",device:b.device||"",rateLimit:data.rateLimit,note:b.note||"",email:b.email||""});
 res.json({id,secret,message,key:{...data,id,packageName:p.name}});
});

app.post("/api/admin/keys/:id/revoke",auth,async(req,res)=>{
 const ref=db.ref("apiKeys/"+req.params.id);if(!(await ref.once("value")).exists())return res.status(404).json({error:"Key not found"});
 await ref.update({status:"revoked",revokedAt:Date.now()});res.json({ok:true});
});

app.get("/api/admin/dashboard",auth,async(req,res)=>{
 const [ps,ks,us]=await Promise.all([db.ref("packages").once("value"),db.ref("apiKeys").once("value"),db.ref("usage").once("value")]);
 const p=ps.val()||{},k=ks.val()||{},u=us.val()||{};
 res.json({packages:Object.keys(p).length,totalKeys:Object.keys(k).length,activeKeys:Object.values(k).filter(x=>x.status==="active").length,requests:Object.values(k).reduce((n,x)=>n+Number(x.requestCount||0),0)+Object.values(u).reduce((n,x)=>n+Number(x.count||0),0)});
});

const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log("API server listening on "+port));
