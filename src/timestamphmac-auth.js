const {smartEncodeUrl} = require('insomnia-url');
const crypto = require('crypto');
const moment = require('moment')

module.exports = function (context) {
  const commaDecodedUrl = smartEncodeUrl(context.request.getUrl(), true);

  const hmac = context.request.getEnvironmentVariable('hmac');

  if(!hmac){
    return
  }

  try {
    var signRequest = false
    
    const appliesTo = hmac.appliesTo ? hmac.appliesTo : [ "sapiti.ovh", "sapiti.net" ]
    appliesTo.forEach((it) => {
      if(commaDecodedUrl.includes(it)){
        signRequest = true
        return 
      }
    })
    if(!signRequest){
      return
    }

    const bodyText = context.request.getBodyText();
    const json = JSON.parse(bodyText? bodyText : '{}');
    const hash = crypto.createHmac('sha256', hmac.privateKey);

    json.timestamp = moment().format();
    json.publickey = hmac.publicKey
    hash.update(json.publickey + json.timestamp, 'utf8');
    json.signature = hash.digest('hex')

    context.request.setBodyText(JSON.stringify(json));

  } catch (err) {
    alert(err.message);
    throw Error(err)
  }
};
