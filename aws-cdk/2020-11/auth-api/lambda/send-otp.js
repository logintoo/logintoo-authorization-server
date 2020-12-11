'use strict';

/**
 * Listens to the cache table stream. Receives records in bunches of up to 10 (settings are in otp-lambda.js).
 * Emails the OTP to a user.
 */

// TODO: Add language/locale support.

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const fs = require('fs');
const path = require('path');

const sysEmailFrom = process.env.SYS_EMAIL_FROM;

// Read email templates from files.
let otpTemplates;
try {
  const otpTemplateHtmlEn = fs.readFileSync(path.join(__dirname, '/otp-email-templates/otp-email-template-en.html'), 'utf8');
  const otpTemplateTextEn = fs.readFileSync(path.join(__dirname, '/otp-email-templates/otp-email-template-en.txt'), 'utf8');

  otpTemplates = {
    en: {html: otpTemplateHtmlEn, text: otpTemplateTextEn}
  };
} 
catch (error) {
  console.error(error);
}

exports.handler = async (event) => {
  const emails = [];

  for (const record of event.Records) {
    if (record.eventName == 'MODIFY' 
      && record.dynamodb.OldImage.otp == undefined
      && typeof record.dynamodb.NewImage.otp == 'object') {
      
      if (!otpTemplates) return new Error('File System Error');

      const appDisplayName = record.dynamodb.NewImage.appDisplayName.S;
      const otpTimeout = record.dynamodb.NewImage.otpTimeout.N;
      const otp = record.dynamodb.NewImage.otp.S;

      const otpEmailLogoSrc = (record.dynamodb.NewImage.otpEmailLogoSrc) ? record.dynamodb.NewImage.otpEmailLogoSrc.S : null;

      let otpEmailLogoImg = '';
      if (otpEmailLogoSrc) {
        otpEmailLogoImg = '<img alt="' + appDisplayName + '" src="' + otpEmailLogoSrc + '" border="0" width="250">';
      }

      const language = 'en';
      const template = otpTemplates[language];

      // Replace placeholders.
      const text = template.text
        .replace(/{{\s*appDisplayName\s*}}/g, appDisplayName)
        .replace(/{{\s*otpTimeout\s*}}/g, otpTimeout)
        .replace(/{{\s*otp\s*}}/g, otp);
      const html = template.html
        .replace(/{{\s*appDisplayName\s*}}/g, appDisplayName)
        .replace(/{{\s*otpTimeout\s*}}/g, otpTimeout)
        .replace(/{{\s*otp\s*}}/g, otp)
        .replace(/{{\s*otpEmailLogo\s*}}/g, otpEmailLogoImg);

      emails.push({
        to: record.dynamodb.NewImage.email.S,
        from: {
          name: appDisplayName,
          email: sysEmailFrom,
        },
        replyTo: record.dynamodb.NewImage.otpEmailFrom.S,
        subject: record.dynamodb.NewImage.otpEmailSubj.S,
        text: text,
        html: html
      });
    }
  }
  
  if (emails.length > 0) {
    try {
      await sgMail.send(emails);

      for (let i = 0, len = emails.length; i < len; i++) {
        console.log('Sent OTP to SendGrid ' + emails[i].to + ' [' + i + ']');
      }
    }
    catch(error) {
      return new Error('SendGrid Error');
    }
  }
};
