import { CognitoJwtVerifier } from "aws-jwt-verify";
import * as client from "openid-client";
import { SSMClient, GetParametersCommand } from "@aws-sdk/client-ssm";
import { getSignedCookies } from "@aws-sdk/cloudfront-signer";

// Cognito User Pool
const userPoolId = process.env.userPoolId;
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const distribDomainName = process.env.distribDomainName;
const cognitoRegion = process.env.cognitoRegion;

// SSM parameters with key for signing Cloudfront signed cookies
const keyPairParam = process.env.keyPairParam;
const privateKeyParam = process.env.privateKeyParam;

// Cookies TTL in hours
const TTLHours = process.env.TTLHours;

export const handler = async (event) => {
  let response;

  try {
    // Get tokens from code grant in querystring
    const codeUrl = new URL(
      `https://${distribDomainName}${event.rawPath}?${event.rawQueryString}`,
    );
    const server = new URL(
      `https://cognito-idp.${cognitoRegion}.amazonaws.com/${userPoolId}`,
    );
    // Authorize code grant (OAuth code flow from Cognito UI)
    let config = await client.discovery(server, clientId, clientSecret);
    let tokens = await client.authorizationCodeGrant(config, codeUrl);

    // Verify access token
    const verifier = CognitoJwtVerifier.create({
      userPoolId,
      tokenUse: "access",
      clientId,
    });
    let verifyPromise = verifier.verify(tokens.access_token);

    // Get SSM parameters that contain private key to sign cloudfront cookies
    const ssm = new SSMClient({ region: cognitoRegion });
    const input = {
      Names: [keyPairParam, privateKeyParam],
      WithDecryption: true,
    };
    const command = new GetParametersCommand(input);
    const paramsPromise = ssm.send(command);

    // Verify token and get SSM parameters in parallel
    const [payload, r] = await Promise.all([verifyPromise, paramsPromise]);

    console.log("Token is valid.");

    const keyPairId = r.Parameters[0].Value;
    const privateKey = r.Parameters[1].Value;

    // Create cloudfront signed cookies
    let date = new Date();
    date.setHours(date.getHours() + TTLHours);
    const url = `https://${distribDomainName}/*`;
    const policy = {
      Statement: [
        {
          Resource: url,
          Condition: {
            DateLessThan: {
              "AWS:EpochTime": Math.round(date.getTime() / 1000), // time in seconds
            },
          },
        },
      ],
    };

    const policyString = JSON.stringify(policy);
    const cookies = getSignedCookies({
      policy: policyString,
      keyPairId,
      privateKey,
    });

    // Set cookie and redirect
    let cookies_array = [];
    for (let i in cookies) {
      cookies_array.push(`${i}=${cookies[i]}; Secure; HttpOnly`);
    }
    response = {
      statusDescription: "Login OK",
      cookies: cookies_array,
    };
  } catch (e) {
    console.log(e);

    // Unset cookie
    response = {
      statusDescription: "Login error",
      cookies: [
        "CloudFront-Key-Pair-Id=''",
        "CloudFront-Signature=''",
        "CloudFront-Policy=''",
      ],
    };
  }

  response.statusCode = "302";
  response.headers = {
    location: `https://${distribDomainName}`,
  };
  return response;
};
