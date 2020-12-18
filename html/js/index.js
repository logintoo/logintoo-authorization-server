/*!
* Logintoo Sample App (https://sample.logintoo.com)
* Copyright (c) 2020, Eduard Moskvin
* BSD 3-Clause License (https://raw.githubusercontent.com/logintoo/logintoo-sample-app/main/LICENSE)
*/

'use strict';

const apiPathAuth = '/auth';
const apiPathOtp = '/otp';

let enterPressed = false;

$(function() {
  // Initializes elements of MaterializeCSS.
  M.AutoInit();

  // Get and validate query string parameters.
  const urlParams = getQueryStringParams();
  const validParams = validateQueryStringParams(urlParams);

  // Show the login form or error message.
  $('#card').children('div').hide();
  if (validParams) {
    $('#email-btn').off('click').click(urlParams, submitEmail);
    $('#email').off('keypress keyup change blur').on('keypress keyup change blur', urlParams, handleKeystrokes);
    $('#login-form').show();
  }
  else {
    $('#error-bad-parameters').show();
  }
  $('#card').fadeIn(400);
  
  // Set focus on the text field.
  M.updateTextFields();
  $('#email').focus();
});

// Get query string parameters.
function getQueryStringParams() {
  const params = new URLSearchParams(window.location.search);

  const output = {
    client_id: params.get('client_id'),
    code_challenge: params.get('code_challenge'),
    code_challenge_method: params.get('code_challenge_method'),
    redirect_uri: params.get('redirect_uri'),
    response_type: params.get('response_type'),
    state: params.get('state')
  };

  if (params.get('language')) {
    output.language = params.get('language');
  }
  if (params.get('locale')) {
    output.locale = params.get('locale');
  }

  return output;
}

// Validate query string parameters.
function validateQueryStringParams(urlParams) {
  if (urlParams.client_id == null) return false;
  if (urlParams.code_challenge == null) return false;
  if (urlParams.code_challenge_method != 'S256') return false;
  if (urlParams.redirect_uri == null) return false;
  if (urlParams.response_type != 'code') return false;
  if (urlParams.state == null) return false;
  
  return true;
}

// Clear validation classes on the input field, submit the form.
function handleKeystrokes(event) {
  switch(event.type) {
    case 'blur':
      if ($(this).val().trim() == '') {
        $(this).removeClass('invalid');
        $(this).removeClass('valid');
      }
      break;

    case 'change':
      $(this).removeClass('invalid');
      $(this).removeClass('valid');
      break;

    case 'keypress':
      if (event.keyCode === 13) {
        enterPressed = true;
      }
      break;

    case 'keyup':
      if (enterPressed && event.keyCode === 13) {
        $(this).blur();
        enterPressed = false;
  
        if ($(this).attr('id') == 'email') {
          submitEmail(event);
        }
        if ($(this).attr('id') == 'access-code') {
          submitCode(event);
        }
      }
      else {
        $(this).removeClass('invalid');
        $(this).removeClass('valid');
      }
      break;
  }
}

// Validate if entered value looks like an access code: 4 to 8 numbers.
function validateTextFieldNumber() {
  const regex = /^[0-9]{4,8}$/;
  const value = $(this).val().trim();

  if (value == '') {
    $(this).removeClass('invalid');
    $(this).removeClass('valid');
    return;
  }
  
  if (regex.test(value)) {
    $(this).removeClass('invalid');
    $(this).addClass('valid');
  }
  else {
    $(this).removeClass('valid');
    $(this).addClass('invalid');
  }
}

// Submit the email address.
async function submitEmail(event) {
  // Rely on the browser's ability to quickly validate email addresses.
  // Full validation will be performed by the API backend.
  if ($('#email:not([class="invalid"]').hasClass('valid')) {
    const email = $('#email').val().trim();

    // Disable the input field and the button.
    $('#email').val('').val(email).prop('disabled', true);
    $('#email-btn').addClass('disabled');
    $('#card-preloader').show();
    
    try {
      // Send a request to the API.
      event.data.email = email;
      let response = await getAPIdata('POST', apiURL + apiPathAuth, event.data);

      if (response.ok) {
        const codeParams = {
          'client_id': event.data.client_id,
          'code_challenge': event.data.code_challenge,
          'email': email
        };
        $('#code-btn').off('click').click(codeParams, submitCode);
        $('#access-code').off('keypress keyup change').on('keypress keyup change', codeParams, handleKeystrokes);
        $('#access-code').off('blur').on('blur', validateTextFieldNumber);

        $('#login-form').hide();
        $('#enter-code').fadeIn(400);
        $('#access-code').focus();
        $('#card-preloader').fadeOut(400);
      }
      else {
        apiFailed(response);
      }
    }
    catch(error) {
      printError('Could not submit the email address', 60000);
    }
  }
  else {
    // Do nothing, just indicate the error.
    $('#email').addClass('invalid').focus();
  }
}

// Submit OTP.
async function submitCode(event) {
  if ($('#access-code:not([class="invalid"]').hasClass('valid')) {
    const otp = $('#access-code').val().trim();

    // Disable the input field and the button.
    $('#access-code').val('').val(otp).prop('disabled', true);
    $('#code-btn').addClass('disabled');
    $('#card-preloader').show();
    
    try {
      // Send a request to the API.
      event.data.otp = otp;
      let response = await getAPIdata('POST', apiURL + apiPathOtp, event.data);

      if (response.ok && response.redirected) {
        // Redirect the user-agent back to the client.
        window.location.assign(response.url);
      }
      else {
        apiFailed(response);
      }
    }
    catch(error) {
      printError('Could not submit the access code', 60000);
    }
  }
  else {
    // Do nothing, just indicate the error.
    $('#access-code').addClass('invalid').focus();
  }
}

// Performs API requests.
function getAPIdata(method, url, data) {
  if (!window.fetch) {
    printError(new Error('Bad browser'));
    return;
  }

  let options = {
    method: method,
    headers: {
      'Content-Type': 'application/json'
    }
  }
  
  if (method != 'GET' && method != 'HEAD' && data) {
    options.body = JSON.stringify(data);
  }
  
  return fetch(url, options);
}

// In case the API request failed.
function apiFailed(response) {
  console.error('API Failed:', response);

  let message = '';

  switch (response.status) {
    case 400: // Bad Request
      message = 'Error: Invalid Request';
      break;

    case 401: // Unauthorized
      message = 'The access code is incorrect. Try again.';

      // Enable the input field and the button.
      $('#access-code').prop('disabled', false).focus();
      $('#access-code').removeClass('invalid');
      $('#access-code').removeClass('valid');
      $('#code-btn').removeClass('disabled');
      $('#card-preloader').hide();

      break;

    case 403: // Forbidden
      $('#card').children('div').hide();
      $('#error-access-denied').show();
      console.log('Access denied');

      // Return here to prevent displaying the toast.
      return;

    case 500: // Internal Server Error
    case 503: // Service Unavailable
      message = 'Service is temporarily unavailable. Try again later.';

      // Enable the input field and the button.
      $('#access-code').prop('disabled', false).focus();
      $('#access-code').removeClass('invalid');
      $('#access-code').removeClass('valid');
      $('#code-btn').removeClass('disabled');
      $('#card-preloader').hide();
      
      break;

    default:
      message = 'Something went wrong. Try again.';
  }
  
  printError(message, 60000);
}

// Sends unobtrusive alerts to the user through toasts.
function printError(error, duration) {
  console.error(error);

  let errMessage;
  if (typeof error === 'object') {
    errMessage = error.message;
  }
  if (typeof error === 'string') {
    errMessage = error;
  }
  if (!errMessage) {
    errMessage = 'Something went wrong';
  }

  M.toast({
    html: errMessage,
    displayLength: duration
  });
}
