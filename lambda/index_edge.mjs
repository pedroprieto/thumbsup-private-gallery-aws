import { CognitoJwtVerifier } from "aws-jwt-verify";
import * as client from "openid-client";
import { SSMClient, GetParametersCommand } from "@aws-sdk/client-ssm";
import { getSignedCookies } from "@aws-sdk/cloudfront-signer";

// TODO: en Lambda@edge no funcionan variables de entorno
const userPoolId = process.env.userPoolId;
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;

export const handler = async (event) => {
  try {
    const cf = event.Records[0].cf;
    console.log(cf);

    const codeUrl = new URL(
      `https://${cf.config.distributionDomainName}${cf.request.uri}?${cf.request.querystring}`,
    );
    console.log(codeUrl);

    const server = new URL(
      "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_xXR3zQv30",
    );

    let config = await client.discovery(server, clientId, clientSecret);
    let tokens = await client.authorizationCodeGrant(config, codeUrl);

    console.log(tokens);

    console.log("Token Endpoint Response", tokens);

    const verifier = CognitoJwtVerifier.create({
      userPoolId,
      tokenUse: "access",
      clientId,
    });

    const payload = await verifier.verify(tokens.access_token);
    console.log("Token is valid. Payload:", payload);

    // Get SSM parameters
    const ssm = new SSMClient({ region: "us-east-1" });
    const input = {
      Names: [
        "/galeriafamiliar/cloudfront_keypair_id",
        "/galeriafamiliar/cloudfront_private_key",
      ],
      WithDecryption: true,
    };
    const command = new GetParametersCommand(input);
    const r = await ssm.send(command);

    const keyPairId = r.Parameters[0].Value;
    const privateKey = r.Parameters[1].Value;

    // Create cookie
    let date = new Date();
    date.setHours(date.getHours() + 1);

    const url = "https://d1btgdqs6cxzvr.cloudfront.net/*";

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

    console.log(cookies);

    let cookies_array = [];
    for (let i in cookies) {
      cookies_array.push({
        key: "set-cookie",
        value: `${i}=${cookies[i]}; Secure; HttpOnly`,
      });
    }

    console.log(cookies_array);

    // Set cookie and redirect

    const response = {
      status: "302",
      statusDescription: "Found",
      headers: {
        location: [
          {
            key: "Location",
            value: "https://d1btgdqs6cxzvr.cloudfront.net/index.html",
          },
        ],
        "set-cookie": cookies_array,
      },
    };
    return response;
  } catch (e) {
    console.log(e);
    // Unset cookie and redirect
  }
};
