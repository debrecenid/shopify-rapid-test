export { };
const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'write_products';
const forwardingAddress = "https://a865b520.ngrok.io";

app.get('/', (req: any, res: any) => {
    res.send(' Wrld!');
});

app.get('/shopify', (req: any, res: any) => {
    console.log('shopify called');
    const shop = req.query.shop;
    if (shop) {
        const state = nonce();
        const redirectUri = forwardingAddress + '/shopify/callback';
        const installUrl = 'https://' + shop +
            '/admin/oauth/authorize?client_id=' + apiKey +
            '&scope=' + scopes +
            '&state=' + state +
            '&redirect_uri=' + redirectUri;

        res.cookie('state', state);
        res.redirect(installUrl);
    } else {
        return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
    }
});

app.get('/shopify/callback', (req: any, res: any) => {
    console.log('callback called')
    const { shop, hmac, code, state } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;

    if (state !== stateCookie) {
        return res.status(403).send('Request origin cannot be verified');
    }

    if (shop && hmac && code) {
        // res.status(200).send('Callback route');
        // DONE: Validate request is from Shopify
        const map = Object.assign({}, req.query);
        delete map['signature'];
        delete map['hmac'];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(
            crypto
                .createHmac('sha256', apiSecret)
                .update(message)
                .digest('hex'),
            'utf-8'
        );
        let hashEquals = false;

        try {
            hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
        } catch (e) {
            hashEquals = false;
        };

        if (!hashEquals) {
            return res.status(400).send('HMAC validation failed');
        }

        // DONE: Exchange temporary code for a permanent access token
        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecret,
            code,
        };

        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
            .then((accessTokenResponse: any) => {
                const accessToken = accessTokenResponse.access_token;
                console.log('accestoken:', accessToken);

                //DONE: Use access token to make API call to 'shop' endpoint
                const shopRequestUrl = 'https://' + shop + '/admin/api/2019-10/shop.json';
                const shopRequestHeaders = {
                    'X-Shopify-Access-Token': accessToken,
                };

                request.get(shopRequestUrl, { headers: shopRequestHeaders })
                    .then((shopResponse:any) => {
                        res.end(shopResponse);
                    })
                    .catch((error:any) => {
                        res.status(error.statusCode).send(error.error.error_description);
                    });
            })
            .catch((error: any) => {
                res.status(error.statusCode).send(error.error.error_description);
            });
    } else {
        res.status(400).send('Required parameters missing');
    }
});

app.listen(3000, () => {
    console.log('Example app listening on port 3000!');
});