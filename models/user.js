const mongoose=require('mongoose');
const crypto = require('crypto');
const uuidv1=require("uuid/v1");

//const { ObjectId }=mongoose.Schema;
const userSchema=new mongoose.Schema({
    name:{
        type:String,
        required:true,
        trim:true
    },
    role:{
        type:Number,
        default:2   
        //0- Admin , 1-teacher , 2-student,3-others
    },
    email:{
        type:String,
        required:true
    },
    phone:{
            type:Number,
            maxlength:10,
            required:true
    },
    
    encrypted_password:{
        type:String,
        required:true
    },
    salt:String
},{ timestamps:true });

userSchema.virtual("password")
          .set(function(password){
              this._password=password;
              this.salt=uuidv1();
              this.encrypted_password=this.securePassword(password);
          })
          .get(function(){
              return this._password;
          });

userSchema.methods={
    authenticate: function(plainpassword){
        return this.securePassword(plainpassword)===this.encrypted_password;
    },
    securePassword: function(plainpassword){
        if(!plainpassword) return "";
        try{
           return crypto.createHmac('sha256', this.salt)
                   .update(plainpassword)
                   .digest('hex');
        }catch(error){
            return error;
        }
    }
}

module.exports=mongoose.model('User',userSchema);