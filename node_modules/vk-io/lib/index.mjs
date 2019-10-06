import nodeHttps, { Agent } from 'https';
import nodeUtil, { inspect as inspect$e } from 'util';
import fetch from 'node-fetch';
import createDebug from 'debug';
import nodeUrl, { URLSearchParams as URLSearchParams$8 } from 'url';
import cheerio from 'cheerio';
import toughCookie from 'tough-cookie';
import nodeCrypto from 'crypto';
import nodeFs from 'fs';
import nodeStream, { PassThrough } from 'stream';
import { SandwichStream } from 'sandwich-stream';
import { noopNext, getOptionalMiddleware, compose } from 'middleware-io';
import nodeHttp from 'http';
import WebSocket from 'ws';

/**
 * Creates a key and value from the keys
 *
 * @param {string[]} keys
 *
 * @return {Object}
 */
const keyMirror = (keys) => {
	const out = {};

	for (const key of keys) {
		out[key] = key;
	}

	return out;
};

/**
 * Returns method for execute
 *
 * @param {string} method
 * @param {Object} params
 *
 * @return {string}
 */
const getExecuteMethod = (method, params = {}) => {
	const options = {};

	for (const [key, value] of Object.entries(params)) {
		options[key] = typeof value === 'object'
			? String(value)
			: value;
	}

	return `API.${method}(${JSON.stringify(options)})`;
};

/**
 * Returns chain for execute
 *
 * @param {Array} methods
 *
 * @return {string}
 */
const getChainReturn = methods => (
	`return [${methods.join(',')}];`
);

/**
 * Resolve task
 *
 * @param {Array} tasks
 * @param {Array} results
 */
const resolveExecuteTask = (tasks, result) => {
	let errors = 0;

	result.response.forEach((response, i) => {
		if (response !== false) {
			tasks[i].resolve(response);

			return;
		}

		tasks[i].reject(result.errors[errors]);

		errors += 1;
	});
};

/**
 * Returns random ID
 *
 * @return {number}
 */
const getRandomId = () => (
	`${Math.floor(Math.random() * 1e4)}${Date.now()}`
);

/**
 * Delay N-ms
 *
 * @param {number} delayed
 *
 * @return {Promise}
 */
const delay = delayed => (
	new Promise(resolve => setTimeout(resolve, delayed))
);

const lt = /&lt;/g;
const qt = /&gt;/g;
const br = /<br>/g;
const amp = /&amp;/g;
const quot = /&quot;/g;

/**
 * Decodes HTML entities
 *
 * @param {string} text
 *
 * @return {string}
 */
const unescapeHTML = text => (
	text
		.replace(lt, '<')
		.replace(qt, '>')
		.replace(br, '\n')
		.replace(amp, '&')
		.replace(quot, '"')
);

/**
 * Copies object params to new object
 *
 * @param {Object} params
 * @param {Array}  properties
 *
 * @return {Object}
 */
const copyParams = (params, properties) => {
	const copies = {};

	for (const property of properties) {
		copies[property] = params[property];
	}

	return copies;
};

/**
 * Displays deprecated message
 *
 * @param {string} message
 */
const showDeprecatedMessage = (message) => {
	// eslint-disable-next-line no-console
	console.log(' \u001b[31mDeprecated:\u001b[39m', message);
};

const { inspect } = nodeUtil;

class Request {
	/**
	 * Constructor
	 *
	 * @param {string} method
	 * @param {Object} params
	 */
	constructor(method, params = {}) {
		this.method = method;
		this.params = { ...params };

		this.attempts = 0;

		this.promise = new Promise((resolve, reject) => {
			this.resolve = resolve;
			this.reject = reject;
		});
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'Request';
	}

	/**
	 * Adds attempt
	 *
	 * @return {number}
	 */
	addAttempt() {
		this.attempts += 1;

		return this.attempts;
	}

	/**
	 * Returns string to execute
	 *
	 * @return {string}
	 */
	toString() {
		return getExecuteMethod(this.method, this.params);
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect.custom](depth, options) {
		const { name } = this.constructor;
		const { method, params, promise } = this;

		const payload = { method, params, promise };

		return `${options.stylize(name, 'special')} ${inspect(payload, options)}`;
	}
}

/**
 * General error class
 */
class VKError extends Error {
    /**
     * Constructor
     */
    constructor({ code, message }) {
        super(message);
        this.code = code;
        this.message = message;
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
    /**
     * Returns custom tag
     */
    get [Symbol.toStringTag]() {
        return this.constructor.name;
    }
    /**
     * Returns property for json
     */
    toJSON() {
        const json = {};
        for (const key of Object.getOwnPropertyNames(this)) {
            json[key] = this[key];
        }
        return json;
    }
}

var version = "4.0.0-rc.19";

/**
 * Chat peer ID
 *
 * @type {number}
 */
const CHAT_PEER = 2e9;

/**
 * Blank html redirect
 *
 * @type {string}
 */
const CALLBACK_BLANK = 'https://oauth.vk.com/blank.html';

/**
 * User-Agent for standalone auth
 *
 * @type {string}
 */
const DESKTOP_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36';

/**
 * Minimum time interval api with error
 *
 * @type {number}
 */
const MINIMUM_TIME_INTERVAL_API = 1133;

/**
 * Default options
 *
 * @type {Object}
 *
 * @property {?string} [token]               Access token
 * @property {Agent}   [agent]               HTTPS agent
 * @property {?string} [language]            The return data language
 *
 * @property {?number} [appId]               Application ID
 * @property {?number} [appSecret]           Secret application key
 *
 * @property {?string} [login]               User login (phone number or email)
 * @property {?string} [phone]               User phone number
 * @property {?string} [password]            User password
 *
 * @property {?number} [authScope]           List of permissions
 * @property {?number} [authTimeout]         Wait time for one auth request
 *
 * @property {string}  [apiMode]             Query mode (sequential|parallel|parallel_selected)
 * @property {number}  [apiWait]             Time to wait before re-querying
 * @property {number}  [apiLimit]            Requests per second
 * @property {number}  [apiVersion]          VK API version
 * @property {string}  [apiBaseUrl]          Base API URL
 * @property {number}  [apiTimeout]          Wait time for one request
 * @property {number}  [apiHeaders]          Headers sent to the API
 * @property {number}  [apiAttempts]         The number of retries at calling
 * @property {number}  [apiExecuteCount]     Number of requests per execute
 * @property {Array}   [apiExecuteMethods]   Methods for call execute (apiMode=parallel_selected)
 *
 * @property {number}  [uploadTimeout]       Wait time for one request
 *
 * @property {number}  [pollingWait]         Time to wait before re-querying
 * @property {number}  [pollingGroupId]      Group ID for polling
 * @property {number}  [pollingAttempts]     The number of retries at calling
 *
 * @property {?string} [webhookSecret]       Webhook secret key
 * @property {?string} [webhookConfirmation] Webhook confirmation key
 *
 * @property {number}  [collectAttempts]     The number of retries at calling
 */
const defaultOptions = {
	token: null,
	agent: null,
	language: null,

	appId: null,
	appSecret: null,

	login: null,
	phone: null,
	password: null,

	authScope: 'all',
	authTimeout: 10e3,

	apiMode: 'sequential',
	apiWait: 3e3,
	apiLimit: 3,
	apiVersion: '5.101',
	apiBaseUrl: 'https://api.vk.com/method',
	apiAttempts: 3,
	apiTimeout: 10e3,
	apiHeaders: {
		'User-Agent': `vk-io/${version} (+https://github.com/negezor/vk-io)`
	},
	apiExecuteCount: 25,
	apiExecuteMethods: ['messages.send'],

	uploadTimeout: 20e3,

	pollingWait: 3e3,
	pollingAttempts: 3,
	pollingGroupId: null,

	webhookSecret: null,
	webhookConfirmation: null,

	collectAttempts: 3
};

/**
 * The attachment types
 *
 * @type {Object}
 */
const attachmentTypes = {
	AUDIO: 'audio',
	AUDIO_MESSAGE: 'audio_message',
	GRAFFITI: 'graffiti',
	DOCUMENT: 'doc',
	GIFT: 'gift',
	LINK: 'link',
	MARKET_ALBUM: 'market_album',
	MARKET: 'market',
	PHOTO: 'photo',
	STICKER: 'sticker',
	VIDEO: 'video',
	WALL_REPLY: 'wall_reply',
	WALL: 'wall',
	POLL: 'poll'
};

/**
 * Default extensions for attachments
 *
 * @type {Object}
 */
const defaultExtensions = {
	photo: 'jpg',
	video: 'mp4',
	audio: 'mp3',
	graffiti: 'png',
	audioMessage: 'ogg'
};

/**
 * Default content type for attachments
 *
 * @type {Object}
 */
const defaultContentTypes = {
	photo: 'image/jpeg',
	video: 'video/mp4',
	audio: 'audio/mp3',
	graffiti: 'image/png',
	audioMessage: 'audio/ogg'
};

/**
 * Sources of captcha
 *
 * @type {Object}
 */
const captchaTypes = keyMirror([
	'API',
	'DIRECT_AUTH',
	'IMPLICIT_FLOW_AUTH',
	'ACCOUNT_VERIFICATION'
]);

/**
 * Message source
 *
 * @type {Object}
 */
const messageSources = {
	USER: 'user',
	CHAT: 'chat',
	GROUP: 'group',
	EMAIL: 'email'
};

/**
 * Resource types
 *
 * @type {Object}
 */
const resourceTypes = {
	USER: 'user',
	GROUP: 'group',
	APPLICATION: 'application'
};

/**
 * API error codes
 *
 * @type {Object}
 */
const apiErrors = {
	UNKNOWN_ERROR: 1,
	APP_SWITCHED_OFF: 2,
	UNKNOWN_METHOD: 3,
	INVALID_SIGNATURE: 4,
	AUTH_FAILURE: 5,
	TOO_MANY_REQUESTS: 6,
	SCOPE_NEEDED: 7,
	INCORRECT_REQUEST: 8,
	TOO_MANY_SIMILAR_ACTIONS: 9,
	INTERNAL_ERROR: 10,
	RESPONSE_SIZE_TOO_BIG: 13,
	CAPTCHA_REQUIRED: 14,
	ACCESS_DENIED: 15,
	USER_VALIDATION_REQUIRED: 17,
	PAGE_BLOCKED: 18,
	STANDALONE_ONLY: 20,
	STANDALONE_AND_OPEN_API_ONLY: 21,
	METHOD_DISABLED: 23,
	CONFIRMATION_REQUIRED: 24,
	GROUP_TOKEN_NOT_VALID: 27,
	APP_TOKEN_NOT_VALID: 28,
	METHOD_CALL_LIMIT: 29,
	PROFILE_IS_PRIVATE: 30,
	WRONG_PARAMETER: 100,
	INVALID_APPLICATION_ID: 101,
	LIMIT_ENTRY_EXHAUSTED: 103,
	INCORRECT_USER_ID: 113,
	INVALID_TIMESTAMP: 150,
	ALBUM_ACCESS_DENIED: 200,
	AUDIO_ACCESS_DENIED: 201,
	GROUP_ACCESS_DENIED: 203,
	ALBUM_OVERFLOW: 300,
	PAYMENTS_DISABLED: 500,
	COMMERCIAL_ACCESS_DENIED: 600,
	COMMERCIAL_ERROR: 603,
	BLACKLISTED_USER: 900,
	MESSAGE_COMMUNITY_BLOCKED_BY_USER: 901,
	MESSAGE_BLOCKED_BY_USER_PRIVACY: 902,
	UNABLE_TO_EDIT_MESSAGE_AFTER_DAY: 909,
	MESSAGE_CANNOT_EDIT_IS_TOO_LONG: 910,
	KEYBOARD_FORMAT_IS_INVALID: 911,
	CHAT_BOT_FEATURE: 912,
	TOO_MANY_FORWARDED_MESSAGES: 913,
	MESSAGE_TOO_LONG: 914,
	NO_ACCESS_TO_CONVERSATION: 917,
	CANNOT_EDIT_THIS_TYPE_MESSAGE: 920,
	UNABLE_TO_FORWARD_MESSAGES: 921,
	UNABLE_TO_DELETE_MESSAGE_FOR_RECIPIENTS: 924,
	NOT_ADMIN_CHAT: 925,
	COMMUNITY_CANNOT_INTERACT_WITH_THIS_PEER: 932,
	CONTACT_NOT_FOUND: 936
};

/**
 * Auth error codes
 *
 * @type {Object}
 */
const authErrors = keyMirror([
	'PAGE_BLOCKED',
	'INVALID_PHONE_NUMBER',
	'AUTHORIZATION_FAILED',
	'FAILED_PASSED_CAPTCHA',
	'FAILED_PASSED_TWO_FACTOR'
]);

/**
 * Upload error codes
 *
 * @type {Object}
 */
const uploadErrors = keyMirror([
	'MISSING_PARAMETERS',
	'NO_FILES_TO_UPLOAD',
	'EXCEEDED_MAX_FILES',
	'UNSUPPORTED_SOURCE_TYPE'
]);

/**
 * Updates error codes
 *
 * @type {Object}
 */
const updatesErrors = keyMirror([
	'NEED_RESTART',
	'POLLING_REQUEST_FAILED'
]);

/**
 * Collect error codes
 *
 * @type {Object}
 */
const collectErrors = keyMirror([
	'EXECUTE_ERROR'
]);

/**
 * Snippets error codes
 *
 * @type {Object}
 */
const snippetsErrors = keyMirror([
	'INVALID_URL',
	'INVALID_RESOURCE',
	'RESOURCE_NOT_FOUND'
]);

/**
 * Snippets error codes
 *
 * @type {Object}
 */
const sharedErrors = keyMirror([
	'MISSING_CAPTCHA_HANDLER',
	'MISSING_TWO_FACTOR_HANDLER'
]);

/**
 * Updates sources
 *
 * @type {Object}
 */
const updatesSources = keyMirror([
	'POLLING',
	'WEBHOOK'
]);

/**
 * List of user permissions and their bit mask
 *
 * @type {Map}
 */
const userScopes = new Map([
	['notify', 1],
	['friends', 2],
	['photos', 4],
	['audio', 8],
	['video', 16],
	['pages', 128],
	['link', 256],
	['status', 1024],
	['notes', 2048],
	['messages', 4096],
	['wall', 8192],
	['ads', 32768],
	['offline', 65536],
	['docs', 131072],
	['groups', 262144],
	['notifications', 524288],
	['stats', 1048576],
	['email', 4194304],
	['market', 134217728]
]);

/**
 * List of group permissions and their bit mask
 *
 * @type {Map}
 */
const groupScopes = new Map([
	['stories', 1],
	['photos', 4],
	// ['app_widget', 64],
	['messages', 4096],
	['docs', 131072],
	['manage', 262144]
]);

/**
 * VK Platforms
 *
 * @type {Map}
 */
const platforms = new Map([
	[1, 'mobile'],
	[2, 'iphone'],
	[3, 'ipad'],
	[4, 'android'],
	[5, 'wphone'],
	[6, 'windows'],
	[7, 'web'],
	[8, 'standalone']
]);

/**
 * Parse attachments with RegExp
 *
 * @type {RegExp}
 */
const parseAttachment = /(photo|video|audio|doc|audio_message|graffiti|wall|market|poll|gift)([-\d]+)_(\d+)_?(\w+)?/;

/**
 * Parse resource with RegExp
 *
 * @type {RegExp}
 */
const parseResource = /(id|club|public|albums|tag|app(?:lication))([-\d]+)/;

/**
 * Parse owner resource with RegExp
 *
 * @type {RegExp}
 */
const parseOwnerResource = /(album|topic|wall|page|videos)([-\d]+)_(\d+)/;

/**
 * Inspect custom data
 *
 * @type {Symbol}
 */
const inspectCustomData = Symbol('inspectCustomData');

const { CAPTCHA_REQUIRED, USER_VALIDATION_REQUIRED, CONFIRMATION_REQUIRED } = apiErrors;
class APIError extends VKError {
    /**
     * Constructor
     */
    constructor(payload) {
        const code = Number(payload.error_code);
        const message = `Code №${code} - ${payload.error_msg}`;
        super({ code, message });
        this.params = payload.request_params;
        if (code === CAPTCHA_REQUIRED) {
            this.captchaSid = Number(payload.captcha_sid);
            this.captchaImg = payload.captcha_img;
        }
        else if (code === USER_VALIDATION_REQUIRED) {
            this.redirectUri = payload.redirect_uri;
        }
        else if (code === CONFIRMATION_REQUIRED) {
            this.confirmationText = payload.confirmation_text;
        }
    }
}

const { DEBUG = '' } = process.env;
const isDebug = DEBUG.includes('vk-io:auth');
class AuthError extends VKError {
    /**
     * Constructor
     */
    constructor({ message, code, pageHtml = null }) {
        super({ message, code });
        this.pageHtml = isDebug
            ? pageHtml
            : null;
    }
}

class UploadError extends VKError {
}

class CollectError extends VKError {
    /**
     * Constructor
     */
    constructor({ message, code, errors }) {
        super({ message, code });
        this.errors = errors;
    }
}

class UpdatesError extends VKError {
}

class ExecuteError extends VKError {
    /**
     * Constructor
     */
    constructor(options) {
        const code = Number(options.error_code);
        const message = `Code №${code} - ${options.error_msg}`;
        super({ code, message });
        this.method = options.method;
    }
}

class SnippetsError extends VKError {
}

class StreamingRuleError extends VKError {
    /**
     * Constructor
     */
    constructor({ message, error_code: code }) {
        super({ message, code });
    }
}

const { URL } = nodeUrl;

/**
 * Returns the entire permission bit mask
 *
 * @return {number}
 */
const getAllUsersPermissions = () => (
	Array.from(userScopes.values()).reduce((previous, current) => (
		previous + current
	), 0)
);

/**
 * Returns the entire permission bit mask
 *
 * @return {number}
 */
const getAllGroupsPermissions = () => (
	Array.from(groupScopes.values()).reduce((previous, current) => (
		previous + current
	), 0)
);

/**
 * Returns the bit mask of the user permission by name
 *
 * @param {Array|string} scope
 *
 * @return {number}
 */
const getUsersPermissionsByName = (scope) => {
	if (!Array.isArray(scope)) {
		scope = scope.split(/,\s{0,}/);
	}

	let bitMask = 0;

	for (const name of scope) {
		if (userScopes.has(name)) {
			bitMask += userScopes.get(name);
		}
	}

	return bitMask;
};

/**
 * Returns the bit mask of the group permission by name
 *
 * @param {Array|string} scope
 *
 * @return {number}
 */
const getGroupsPermissionsByName = (scope) => {
	if (!Array.isArray(scope)) {
		scope = scope.split(/,\s{0,}/);
	}

	let bitMask = 0;

	for (const name of scope) {
		if (groupScopes.has(name)) {
			bitMask += groupScopes.get(name);
		}
	}

	return bitMask;
};

/**
 * Parse form
 *
 * @param {Cheerio} $
 *
 * @return {Object}
 */
const parseFormField = ($) => {
	const $form = $('form[action][method]');

	const fields = {};

	for (const { name, value } of $form.serializeArray()) {
		fields[name] = value;
	}

	return {
		action: $form.attr('action'),
		fields
	};
};

/**
 * Returns full URL use Response
 *
 * @param {string}   action
 * @param {Response} response
 *
 * @type {URL}
 */
const getFullURL = (action, { url }) => {
	if (action.startsWith('https://')) {
		return new URL(action);
	}

	const { protocol, host } = new URL(url);

	return new URL(action, `${protocol}//${host}`);
};

const { promisify } = nodeUtil;

const debug = createDebug('vk-io:util:fetch-cookie');

const REDIRECT_CODES = [303, 301, 302];

const { CookieJar } = toughCookie;

const USER_AGENT_RE = /^User-Agent$/i;

const findUserAgent = (headers) => {
	if (!headers) {
		return null;
	}

	const key = Object.keys(headers)
		.find(header => USER_AGENT_RE.test(header));

	if (!key) {
		return null;
	}

	return headers[key];
};

const fetchCookieDecorator = (jar = new CookieJar()) => {
	const setCookie = promisify(jar.setCookie).bind(jar);
	const getCookieString = promisify(jar.getCookieString).bind(jar);

	return async function fetchCookie(url, options = {}) {
		const previousCookie = await getCookieString(url);

		const { headers = {} } = options;

		if (previousCookie) {
			headers.cookie = previousCookie;
		}

		debug('fetch url %s', url);

		const response = await fetch(url, {
			...options,

			headers
		});

		const { 'set-cookie': cookies = [] } = response.headers.raw();

		if (cookies.length === 0) {
			return response;
		}

		await Promise.all(cookies.map(cookie => (
			setCookie(cookie, response.url)
		)));

		return response;
	};
};

const fetchCookieFollowRedirectsDecorator = (jar) => {
	const fetchCookie = fetchCookieDecorator(jar);

	return async function fetchCookieFollowRedirects(url, options = {}) {
		const response = await fetchCookie(url, {
			...options,

			redirect: 'manual'
		});

		const isRedirect = REDIRECT_CODES.includes(response.status);

		if (isRedirect && options.redirect !== 'manual' && options.follow !== 0) {
			debug('Redirect to', response.headers.get('location'));

			let follow;
			if (options.follow) {
				follow = options.follow - 1;
			}

			const userAgent = findUserAgent(options.headers);

			const headers = userAgent
				? { 'User-Agent': userAgent }
				: {};

			const redirectResponse = await fetchCookieFollowRedirects(response.headers.get('location'), {
				method: 'GET',
				body: null,
				headers,
				follow
			});

			return redirectResponse;
		}

		return response;
	};
};

const { load: cheerioLoad } = cheerio;

const { URL: URL$1, URLSearchParams } = nodeUrl;

const debug$1 = createDebug('vk-io:auth:account-verification');

const {
	INVALID_PHONE_NUMBER,
	AUTHORIZATION_FAILED,
	FAILED_PASSED_CAPTCHA,
	FAILED_PASSED_TWO_FACTOR
} = authErrors;

/**
 * Two-factor auth check action
 *
 * @type {string}
 */
const ACTION_AUTH_CODE = 'act=authcheck';

/**
 * Phone number check action
 *
 * @type {string}
 */
const ACTION_SECURITY_CODE = 'act=security';

/**
 * Bind a phone to a page
 *
 * @type {string}
 */
const ACTION_VALIDATE = 'act=validate';

/**
 * Bind a phone to a page action
 *
 * @type {string}
 */
const ACTION_CAPTCHA = 'act=captcha';

/**
 * Number of two-factorial attempts
 *
 * @type {number}
 */
const TWO_FACTOR_ATTEMPTS = 3;

class AccountVerification {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		const { agent, login, phone } = vk.options;

		this.login = login;
		this.phone = phone;

		this.agent = agent;

		this.jar = new CookieJar();
		this.fetchCookie = fetchCookieFollowRedirectsDecorator(this.jar);

		this.captchaValidate = null;
		this.captchaAttempts = 0;

		this.twoFactorValidate = null;
		this.twoFactorAttempts = 0;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'AccountVerification';
	}

	/**
	 * Executes the HTTP request
	 *
	 * @param {string} url
	 * @param {Object} options
	 *
	 * @return {Promise<Response>}
	 */
	fetch(url, options = {}) {
		const { agent } = this;

		const { headers = {} } = options;

		return this.fetchCookie(url, {
			...options,

			agent,
			timeout: this.vk.options.authTimeout,
			compress: false,

			headers: {
				...headers,

				'User-Agent': DESKTOP_USER_AGENT
			}
		});
	}

	/**
	 * Runs authorization
	 *
	 * @return {Promise<Object>}
	 */
	// eslint-disable-next-line consistent-return
	async run(redirectUri) {
		let response = await this.fetch(redirectUri, {
			method: 'GET'
		});

		const isProcessed = true;

		while (isProcessed) {
			const { url } = response;

			if (url.includes(CALLBACK_BLANK)) {
				let { hash } = new URL$1(response.url);

				if (hash.startsWith('#')) {
					hash = hash.substring(1);
				}

				const params = new URLSearchParams(hash);

				if (params.has('error')) {
					throw new AuthError({
						message: `Failed passed grant access: ${params.get('error_description') || 'Unknown error'}`,
						code: AUTHORIZATION_FAILED
					});
				}

				const user = params.get('user_id');

				return {
					user: user !== null
						? Number(user)
						: null,

					token: params.get('access_token')
				};
			}

			const $ = cheerioLoad(await response.text());

			if (url.includes(ACTION_AUTH_CODE)) {
				response = await this.processTwoFactorForm(response, $);

				continue;
			}

			if (url.includes(ACTION_SECURITY_CODE)) {
				response = await this.processSecurityForm(response, $);

				continue;
			}

			if (url.includes(ACTION_VALIDATE)) {
				response = await this.processValidateForm(response, $);

				continue;
			}

			if (url.includes(ACTION_CAPTCHA)) {
				response = await this.processCaptchaForm(response, $);

				continue;
			}

			throw new AuthError({
				message: 'Account verification failed',
				code: AUTHORIZATION_FAILED
			});
		}
	}

	/**
	 * Process two-factor form
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	async processTwoFactorForm(response, $) {
		debug$1('process two-factor handle');

		if (this.twoFactorValidate !== null) {
			this.twoFactorValidate.reject(new AuthError({
				message: 'Incorrect two-factor code',
				code: FAILED_PASSED_TWO_FACTOR,
				pageHtml: $.html()
			}));

			this.twoFactorAttempts += 1;
		}

		if (this.twoFactorAttempts >= TWO_FACTOR_ATTEMPTS) {
			throw new AuthError({
				message: 'Failed passed two-factor authentication',
				code: FAILED_PASSED_TWO_FACTOR
			});
		}

		const { action, fields } = parseFormField($);

		const { code, validate } = await this.vk.callbackService.processingTwoFactor({});

		fields.code = code;

		try {
			const url = getFullURL(action, response);

			response = await this.fetch(url, {
				method: 'POST',
				body: new URLSearchParams(fields)
			});

			return response;
		} catch (error) {
			validate.reject(error);

			throw error;
		}
	}

	/**
	 * Process security form
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	async processSecurityForm(response, $) {
		debug$1('process security form');

		const { login, phone } = this;

		let number;
		if (phone !== null) {
			number = phone;
		} else if (login !== null && !login.includes('@')) {
			number = login;
		} else {
			throw new AuthError({
				message: 'Missing phone number in the phone or login field',
				code: INVALID_PHONE_NUMBER
			});
		}

		if (typeof number === 'string') {
			number = number.trim().replace(/^(\+|00)/, '');
		}

		number = String(number);

		const $field = $('.field_prefix');

		const prefix = $field.first().text().trim().replace('+', '').length;
		const postfix = $field.last().text().trim().length;

		const { action, fields } = parseFormField($);

		fields.code = number.slice(prefix, number.length - postfix);

		const url = getFullURL(action, response);

		response = await this.fetch(url, {
			method: 'POST',
			body: new URLSearchParams(fields)
		});

		if (response.url.includes(ACTION_SECURITY_CODE)) {
			throw new AuthError({
				message: 'Invalid phone number',
				code: INVALID_PHONE_NUMBER
			});
		}

		return response;
	}

	/**
	 * Process validation form
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	processValidateForm(response, $) {
		const href = $('#activation_wrap a').attr('href');
		const url = getFullURL(href, response);

		return this.fetch(url, {
			method: 'GET'
		});
	}

	/**
	 * Process captcha form
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	async processCaptchaForm(response, $) {
		if (this.captchaValidate !== null) {
			this.captchaValidate.reject(new AuthError({
				message: 'Incorrect captcha code',
				code: FAILED_PASSED_CAPTCHA
			}));

			this.captchaValidate = null;

			this.captchaAttempts += 1;
		}

		const { action, fields } = parseFormField($);

		const src = $('.captcha_img').attr('src');

		const { key, validate } = await this.vk.callbackService.processingCaptcha({
			type: captchaTypes.ACCOUNT_VERIFICATION,
			sid: fields.captcha_sid,
			src
		});

		this.captchaValidate = validate;

		fields.captcha_key = key;

		const url = getFullURL(action, response);

		url.searchParams.set('utf8', 1);

		const pageResponse = await this.fetch(url, {
			method: 'POST',
			body: new URLSearchParams(fields)
		});

		return pageResponse;
	}
}

function sequential(next) {
	this.callMethod(this.queue.shift());

	next();
}

async function parallel(next) {
	const { queue } = this;

	if (queue[0].method.startsWith('execute')) {
		sequential.call(this, next);

		return;
	}

	// Wait next event loop, saves one request or more
	await delay(0);

	const { apiExecuteCount } = this.vk.options;

	const tasks = [];
	const chain = [];

	for (let i = 0; i < queue.length; i += 1) {
		if (queue[i].method.startsWith('execute')) {
			continue;
		}

		const request = queue.splice(i, 1)[0];

		i -= 1;

		tasks.push(request);
		chain.push(String(request));

		if (tasks.length >= apiExecuteCount) {
			break;
		}
	}

	try {
		const request = new Request('execute', {
			code: getChainReturn(chain)
		});

		this.callMethod(request);

		next();

		resolveExecuteTask(tasks, await request.promise);
	} catch (error) {
		for (const task of tasks) {
			task.reject(error);
		}
	}
}

async function parallelSelected(next) {
	const { apiExecuteMethods, apiExecuteCount } = this.vk.options;

	const { queue } = this;

	if (!apiExecuteMethods.includes(queue[0].method)) {
		sequential.call(this, next);

		return;
	}

	// Wait next event loop, saves one request or more
	await delay(0);

	const tasks = [];
	const chain = [];

	for (let i = 0; i < queue.length; i += 1) {
		if (!apiExecuteMethods.includes(queue[i].method)) {
			continue;
		}

		const request = queue.splice(i, 1)[0];

		i -= 1;

		tasks.push(request);
		chain.push(String(request));

		if (tasks.length >= apiExecuteCount) {
			break;
		}
	}

	if (tasks.length === 0) {
		sequential.call(this, next);

		return;
	}

	try {
		const request = new Request('execute', {
			code: getChainReturn(chain)
		});

		this.callMethod(request);

		next();

		resolveExecuteTask(tasks, await request.promise);
	} catch (error) {
		for (const task of tasks) {
			task.reject(error);
		}
	}
}

const { inspect: inspect$1 } = nodeUtil;
const { URLSearchParams: URLSearchParams$1 } = nodeUrl;

const {
	CAPTCHA_REQUIRED: CAPTCHA_REQUIRED$1,
	TOO_MANY_REQUESTS,
	USER_VALIDATION_REQUIRED: USER_VALIDATION_REQUIRED$1
} = apiErrors;

const debug$2 = createDebug('vk-io:api');

const requestHandlers = {
	sequential,
	parallel,
	parallel_selected: parallelSelected
};

/**
 * Returns request handler
 *
 * @param {string} mode
 *
 * @return {Function}
 */
const getRequestHandler = (mode = 'sequential') => {
	const handler = requestHandlers[mode];

	if (!handler) {
		throw new VKError({
			message: 'Unsuported api mode'
		});
	}

	return handler;
};

const groupMethods = [
	'account',
	'ads',
	'appWidgets',
	'apps',
	'audio',
	'auth',
	'board',
	'database',
	'docs',
	'fave',
	'friends',
	'gifts',
	'groups',
	'leads',
	'leadForms',
	'likes',
	'market',
	'messages',
	'newsfeed',
	'notes',
	'notifications',
	'orders',
	'pages',
	'photos',
	'places',
	'polls',
	'podcasts',
	'prettyCards',
	'search',
	'secure',
	'stats',
	'status',
	'storage',
	'stories',
	'streaming',
	'users',
	'utils',
	'video',
	'wall',
	'widgets'
];

/**
 * Working with API methods
 *
 * @public
 */
class API {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.queue = [];
		this.started = false;
		this.suspended = false;

		for (const group of groupMethods) {
			const isMessagesGroup = group === 'messages';

			/**
			 * NOTE: Optimization for other methods
			 *
			 * Instead of checking everywhere the presence of a property in an object
			 * The check is only for the messages group
			 * Since it is necessary to change the behavior of the sending method
			 */
			this[group] = new Proxy(
				isMessagesGroup
					? {
						send: (params = {}) => {
							if (!('random_id' in params)) {
								params = {
									...params,

									random_id: getRandomId()
								};
							}

							return this.enqueue('messages.send', params);
						}
					}
					: {},
				{
					get: isMessagesGroup
						? (obj, prop) => obj[prop] || (
							params => (
								this.enqueue(`${group}.${prop}`, params)
							)
						)
						: (obj, prop) => params => (
							this.enqueue(`${group}.${prop}`, params)
						)
				}
			);
		}
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'API';
	}

	/**
	 * Returns the current used API version
	 *
	 * @return {string}
	 */
	get API_VERSION() {
		return this.vk.options.apiVersion;
	}

	/**
	 * Call execute method
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	execute(params) {
		return this.enqueue('execute', params);
	}

	/**
	 * Call execute procedure
	 *
	 * @param {string} name
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	procedure(name, params) {
		return this.enqueue(`execute.${name}`, params);
	}

	/**
	 * Call raw method
	 *
	 * @param {string} method
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	call(method, params) {
		return this.enqueue(method, params);
	}

	/**
	 * Adds request for queue
	 *
	 * @param {Request} request
	 *
	 * @return {Promise<Object>}
	 */
	callWithRequest(request) {
		this.queue.push(request);

		this.worker();

		return request.promise;
	}

	/**
	 * Adds method to queue
	 *
	 * @param {string} method
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	enqueue(method, params) {
		const request = new Request(method, params);

		return this.callWithRequest(request);
	}

	/**
	 * Adds an element to the beginning of the queue
	 *
	 * @param {Request} request
	 */
	requeue(request) {
		this.queue.unshift(request);

		this.worker();
	}

	/**
	 * Running queue
	 */
	worker() {
		if (this.started) {
			return;
		}

		this.started = true;

		const { apiLimit, apiMode } = this.vk.options;

		const handler = getRequestHandler(apiMode);
		const interval = Math.round(MINIMUM_TIME_INTERVAL_API / apiLimit);

		const work = () => {
			if (this.queue.length === 0 || this.suspended) {
				this.started = false;

				return;
			}

			handler.call(this, () => {
				setTimeout(work, interval);
			});
		};

		work();
	}

	/**
	 * Calls the api method
	 *
	 * @param {Request} request
	 */
	async callMethod(request) {
		const { options } = this.vk;
		const { method } = request;

		const params = {
			access_token: options.token,
			v: options.apiVersion,

			...request.params
		};

		if (options.language !== null) {
			params.lang = options.language;
		}

		debug$2(`http --> ${method}`);

		const startTime = Date.now();

		let response;
		try {
			response = await fetch(`${options.apiBaseUrl}/${method}`, {
				method: 'POST',
				compress: false,
				agent: options.agent,
				timeout: options.apiTimeout,
				headers: {
					...options.apiHeaders,

					connection: 'keep-alive'
				},
				body: new URLSearchParams$1(params)
			});

			response = await response.json();
		} catch (error) {
			if (request.addAttempt() <= options.apiAttempts) {
				await delay(options.apiWait);

				debug$2(`Request ${method} restarted ${request.attempts} times`);

				this.requeue(request);

				return;
			}

			if ('captchaValidate' in request) {
				request.captchaValidate.reject(error);
			}

			request.reject(error);

			return;
		}

		const endTime = (Date.now() - startTime).toLocaleString();

		debug$2(`http <-- ${method} ${endTime}ms`);

		if ('error' in response) {
			this.handleError(request, new APIError(response.error));

			return;
		}

		if ('captchaValidate' in request) {
			request.captchaValidate.resolve();
		}

		if (method.startsWith('execute')) {
			request.resolve({
				response: response.response,
				errors: (response.execute_errors || []).map(error => (
					new ExecuteError(error)
				))
			});

			return;
		}

		request.resolve(
			response.response !== undefined
				? response.response
				: response
		);
	}

	/**
	 * Error API handler
	 *
	 * @param {Request} request
	 * @param {Object}  error
	 */
	async handleError(request, error) {
		const { code } = error;

		if (code === TOO_MANY_REQUESTS) {
			if (this.suspended) {
				this.requeue(request);

				return;
			}

			this.suspended = true;

			await delay((MINIMUM_TIME_INTERVAL_API / this.vk.options.apiLimit) + 50);

			this.suspended = false;

			this.requeue(request);

			return;
		}

		if ('captchaValidate' in request) {
			request.captchaValidate.reject(error);
		}

		if (code === USER_VALIDATION_REQUIRED$1) {
			if (this.suspended) {
				this.requeue(request);
			}

			this.suspended = true;

			try {
				const verification = new AccountVerification(this.vk);

				const { token } = await verification.run(error.redirectUri);

				debug$2('Account verification passed');

				this.vk.token = token;

				this.suspended = false;

				this.requeue(request);
			} catch (verificationError) {
				debug$2('Account verification error', verificationError);

				request.reject(error);

				await delay(15e3);

				this.suspended = false;

				this.worker();
			}

			return;
		}

		if (code !== CAPTCHA_REQUIRED$1 || !this.vk.callbackService.hasCaptchaHandler) {
			request.reject(error);

			return;
		}

		try {
			const { captchaSid } = error;

			const { key, validate } = await this.vk.callbackService.processingCaptcha({
				type: captchaTypes.API,
				src: error.captchaImg,
				sid: captchaSid,
				request
			});

			request.captchaValidate = validate;

			request.params.captcha_sid = captchaSid;
			request.params.captcha_key = key;

			this.requeue(request);
		} catch (e) {
			request.reject(e);
		}
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$1.custom](depth, options) {
		const { name } = this.constructor;
		const { started, queue } = this;

		const payload = { started, queue };

		return `${options.stylize(name, 'special')} ${inspect$1(payload, options)}`;
	}
}

const { load: cheerioLoad$1 } = cheerio;

const { URL: URL$2, URLSearchParams: URLSearchParams$2 } = nodeUrl;

const debug$3 = createDebug('vk-io:auth:direct');

const {
	INVALID_PHONE_NUMBER: INVALID_PHONE_NUMBER$1,
	AUTHORIZATION_FAILED: AUTHORIZATION_FAILED$1,
	FAILED_PASSED_CAPTCHA: FAILED_PASSED_CAPTCHA$1,
	FAILED_PASSED_TWO_FACTOR: FAILED_PASSED_TWO_FACTOR$1
} = authErrors;

/**
 * Number of two-factorial attempts
 *
 * @type {number}
 */
const TWO_FACTOR_ATTEMPTS$1 = 3;

/**
 * Number of captcha attempts
 *
 * @type {number}
 */
const CAPTCHA_ATTEMPTS = 3;

/**
 * Phone number check action
 *
 * @type {string}
 */
const ACTION_SECURITY_CODE$1 = 'act=security';

class DirectAuth {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} options
	 */
	constructor(vk, {
		appId = vk.options.appId,
		appSecret = vk.options.appSecret,

		login = vk.options.login,
		phone = vk.options.phone,
		password = vk.options.password,

		scope = vk.options.authScope,
		agent = vk.options.agent,
		timeout = vk.options.authTimeout,

		apiVersion = vk.options.apiVersion
	} = {}) {
		this.vk = vk;

		this.appId = appId;
		this.appSecret = appSecret;

		this.login = login;
		this.phone = phone;
		this.password = password;

		this.agent = agent;
		this.scope = scope;
		this.timeout = timeout;

		this.apiVersion = apiVersion;

		this.started = false;

		this.captchaValidate = null;
		this.captchaAttempts = 0;

		this.twoFactorValidate = null;
		this.twoFactorAttempts = 0;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'DirectAuth';
	}

	/**
	 * Executes the HTTP request
	 *
	 * @param {string} url
	 * @param {Object} options
	 *
	 * @return {Promise<Response>}
	 */
	fetch(url, options = {}) {
		const { agent, timeout } = this;

		const { headers = {} } = options;

		return this.fetchCookie(url, {
			...options,

			agent,
			timeout,
			compress: false,

			headers: {
				...headers,

				'User-Agent': DESKTOP_USER_AGENT
			}
		});
	}

	/**
	 * Returns permission page
	 *
	 * @param {Object} query
	 *
	 * @return {Response}
	 */
	getPermissionsPage(query = {}) {
		let { scope } = this;

		if (scope === 'all' || scope === null) {
			scope = getAllUsersPermissions();
		} else if (typeof scope !== 'number') {
			scope = getUsersPermissionsByName(scope);
		}

		debug$3('auth scope %s', scope);

		const {
			appId,
			appSecret,
			login,
			phone,
			password
		} = this;

		const params = new URLSearchParams$2({
			...query,
			username: login || phone,
			grant_type: 'password',
			client_secret: appSecret,
			'2fa_supported': this.vk.callbackService.hasTwoFactorHandler
				? 1
				: 0,
			v: this.apiVersion,
			client_id: appId,
			password,
			scope
		});

		const url = new URL$2(`https://oauth.vk.com/token?${params}`);

		return this.fetch(url, {
			method: 'GET'
		});
	}

	/**
	 * Runs authorization
	 *
	 * @return {Promise<Object>}
	 */
	// eslint-disable-next-line consistent-return
	async run() {
		if (this.started) {
			throw new AuthError({
				message: 'Authorization already started!',
				code: AUTHORIZATION_FAILED$1
			});
		}

		this.started = true;

		this.fetchCookie = fetchCookieFollowRedirectsDecorator();

		let response = await this.getPermissionsPage();
		let text;

		const isProcessed = true;

		while (isProcessed) {
			text = await response.text();

			let isJSON = true;
			try {
				text = JSON.parse(text);
			} catch (e) {
				isJSON = false;
			}

			if (isJSON) {
				if ('access_token' in text) {
					const {
						email = null,
						user_id: user = null,
						expires_in: expires = null,
						access_token: token
					} = text;

					return {
						email,
						user: user !== null
							? Number(user)
							: null,

						token,
						expires: expires !== null
							? Number(expires)
							: null
					};
				}

				if ('error' in text) {
					if (text.error === 'invalid_client') {
						throw new AuthError({
							message: `Invalid client (${text.error_description})`,
							code: AUTHORIZATION_FAILED$1
						});
					}

					if (text.error === 'need_captcha') {
						response = await this.processCaptcha(text);

						continue;
					}

					if (text.error === 'need_validation') {
						if ('validation_type' in text) {
							response = await this.processTwoFactor(text);

							continue;
						}

						const $ = cheerioLoad$1(text);

						response = this.processSecurityForm(response, $);

						continue;
					}

					throw new AuthError({
						message: 'Unsupported type validation',
						code: AUTHORIZATION_FAILED$1
					});
				}
			}

			throw new AuthError({
				message: 'Authorization failed',
				code: AUTHORIZATION_FAILED$1
			});
		}
	}

	/**
	 * Process captcha
	 *
	 * @param {Object} payload
	 *
	 * @return {Response}
	 */
	async processCaptcha({ captcha_sid: sid, captcha_img: src }) {
		debug$3('captcha process');

		if (this.captchaValidate !== null) {
			this.captchaValidate.reject(new AuthError({
				message: 'Incorrect captcha code',
				code: FAILED_PASSED_CAPTCHA$1
			}));

			this.captchaValidate = null;

			this.captchaAttempts += 1;
		}

		if (this.captchaAttempts >= CAPTCHA_ATTEMPTS) {
			throw new AuthError({
				message: 'Maximum attempts passage captcha',
				code: FAILED_PASSED_CAPTCHA$1
			});
		}

		const { key, validate } = await this.vk.callbackService.processingCaptcha({
			type: captchaTypes.DIRECT_AUTH,
			sid,
			src
		});

		this.captchaValidate = validate;

		const response = await this.getPermissionsPage({
			captcha_sid: sid,
			captcha_key: key
		});

		return response;
	}

	/**
	 * Process two-factor
	 *
	 * @param {Object} response
	 *
	 * @return {Promise<Response>}
	 */
	async processTwoFactor({ validation_type: validationType, phone_mask: phoneMask }) {
		debug$3('process two-factor handle');

		if (this.twoFactorValidate !== null) {
			this.twoFactorValidate.reject(new AuthError({
				message: 'Incorrect two-factor code',
				code: FAILED_PASSED_TWO_FACTOR$1
			}));

			this.twoFactorValidate = null;

			this.twoFactorAttempts += 1;
		}

		if (this.twoFactorAttempts >= TWO_FACTOR_ATTEMPTS$1) {
			throw new AuthError({
				message: 'Failed passed two-factor authentication',
				code: FAILED_PASSED_TWO_FACTOR$1
			});
		}

		const { code, validate } = await this.vk.callbackService.processingTwoFactor({
			phoneMask,
			type: validationType === '2fa_app'
				? 'app'
				: 'sms'
		});

		this.twoFactorValidate = validate;

		const response = await this.getPermissionsPage({ code });

		return response;
	}

	/**
	 * Process security form
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	async processSecurityForm(response, $) {
		debug$3('process security form');

		const { login, phone } = this;

		let number;
		if (phone !== null) {
			number = phone;
		} else if (login !== null && !login.includes('@')) {
			number = login;
		} else {
			throw new AuthError({
				message: 'Missing phone number in the phone or login field',
				code: INVALID_PHONE_NUMBER$1
			});
		}

		if (typeof number === 'string') {
			number = number.trim().replace(/^(\+|00)/, '');
		}

		number = String(number);

		const $field = $('.field_prefix');

		const prefix = $field.first().text().trim().replace('+', '').length;
		const postfix = $field.last().text().trim().length;

		const { action, fields } = parseFormField($);

		fields.code = number.slice(prefix, number.length - postfix);

		const url = getFullURL(action, response);

		response = await this.fetch(url, {
			method: 'POST',
			body: new URLSearchParams$2(fields)
		});

		if (response.url.includes(ACTION_SECURITY_CODE$1)) {
			throw new AuthError({
				message: 'Invalid phone number',
				code: INVALID_PHONE_NUMBER$1
			});
		}

		return response;
	}
}

const { load: cheerioLoad$2 } = cheerio;

const { URL: URL$3, URLSearchParams: URLSearchParams$3 } = nodeUrl;
const { promisify: promisify$1 } = nodeUtil;

const debug$4 = createDebug('vk-io:auth:implicit-flow');

const {
	PAGE_BLOCKED,
	INVALID_PHONE_NUMBER: INVALID_PHONE_NUMBER$2,
	AUTHORIZATION_FAILED: AUTHORIZATION_FAILED$2,
	FAILED_PASSED_CAPTCHA: FAILED_PASSED_CAPTCHA$2,
	FAILED_PASSED_TWO_FACTOR: FAILED_PASSED_TWO_FACTOR$2
} = authErrors;

/**
 * Blocked action
 *
 * @type {string}
 */
const ACTION_BLOCKED = 'act=blocked';

/**
 * Two-factor auth check action
 *
 * @type {string}
 */
const ACTION_AUTH_CODE$1 = 'act=authcheck';

/**
 * Phone number check action
 *
 * @type {string}
 */
const ACTION_SECURITY_CODE$2 = 'act=security';

/**
 * Number of two-factorial attempts
 *
 * @type {number}
 */
const TWO_FACTOR_ATTEMPTS$2 = 3;

/**
 * Number of captcha attempts
 *
 * @type {number}
 */
const CAPTCHA_ATTEMPTS$1 = 3;

/**
 * Removes the prefix
 *
 * @type {RegExp}
 */
const REPLACE_PREFIX_RE = /^[+|0]+/;

/**
 * Find location.href text
 *
 * @type {RegExp}
 */
const FIND_LOCATION_HREF_RE = /location\.href\s+=\s+"([^"]+)"/i;

class ImplicitFlow {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} options
	 */
	constructor(vk, {
		appId = vk.options.appId,
		appSecret = vk.options.appSecret,

		login = vk.options.login,
		phone = vk.options.phone,
		password = vk.options.password,

		agent = vk.options.agent,
		scope = vk.options.authScope,
		timeout = vk.options.authTimeout,

		apiVersion = vk.options.apiVersion
	} = {}) {
		this.vk = vk;

		this.appId = appId;
		this.appSecret = appSecret;

		this.login = login;
		this.phone = phone;
		this.password = password;

		this.agent = agent;
		this.scope = scope;
		this.timeout = timeout;

		this.apiVersion = apiVersion;

		this.jar = new CookieJar();

		this.started = false;

		this.captchaValidate = null;
		this.captchaAttempts = 0;

		this.twoFactorValidate = null;
		this.twoFactorAttempts = 0;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}

	/**
	 * Returns CookieJar
	 *
	 * @return {CookieJar}
	 */
	get cookieJar() {
		return this.jar;
	}

	/**
	 * Sets the CookieJar
	 *
	 * @param {CookieJar} jar
	 *
	 * @return {this}
	 */
	set cookieJar(jar) {
		this.jar = jar;
	}

	/**
	 * Returns cookie
	 *
	 * @return {Promise<Object>}
	 */
	async getCookies() {
		const { jar } = this;

		const getCookieString = promisify$1(jar.getCookieString).bind(jar);

		const [login, main] = await Promise.all([
			getCookieString('https://login.vk.com'),
			getCookieString('https://vk.com')
		]);

		return {
			'login.vk.com': login,
			'vk.com': main
		};
	}

	/**
	 * Executes the HTTP request
	 *
	 * @param {string} url
	 * @param {Object} options
	 *
	 * @return {Promise<Response>}
	 */
	fetch(url, options = {}) {
		const { agent, timeout } = this;

		const { headers = {} } = options;

		return this.fetchCookie(url, {
			...options,

			agent,
			timeout,
			compress: false,

			headers: {
				...headers,

				'User-Agent': DESKTOP_USER_AGENT
			}
		});
	}

	/**
	 * Runs authorization
	 *
	 * @return {Promise<Object>}
	 */
	// eslint-disable-next-line consistent-return
	async run() {
		if (this.started) {
			throw new AuthError({
				message: 'Authorization already started!',
				code: AUTHORIZATION_FAILED$2
			});
		}

		this.started = true;

		this.fetchCookie = fetchCookieFollowRedirectsDecorator(this.jar);

		debug$4('get permissions page');

		let response = await this.getPermissionsPage();

		const isProcessed = true;

		while (isProcessed) {
			const { url } = response;

			debug$4('URL', url);

			if (url.includes(CALLBACK_BLANK)) {
				return { response };
			}

			if (url.includes(ACTION_BLOCKED)) {
				debug$4('page blocked');

				throw new AuthError({
					message: 'Page blocked',
					code: PAGE_BLOCKED
				});
			}

			const $ = cheerioLoad$2(await response.text());

			if (url.includes(ACTION_AUTH_CODE$1)) {
				response = await this.processTwoFactorForm(response, $);

				continue;
			}

			if (url.includes(ACTION_SECURITY_CODE$2)) {
				response = await this.processSecurityForm(response, $);

				continue;
			}

			const $error = $('.box_error');
			const $service = $('.service_msg_warning');

			const isError = $error.length !== 0;

			if (this.captchaValidate === null && (isError || $service.length !== 0)) {
				const errorText = isError
					? $error.text()
					: $service.text();

				throw new AuthError({
					message: `Auth form error: ${errorText}`,
					code: AUTHORIZATION_FAILED$2,
					pageHtml: $.html()
				});
			}

			if ($('input[name="pass"]').length !== 0) {
				response = await this.processAuthForm(response, $);

				continue;
			}

			if (url.includes('act=')) {
				throw new AuthError({
					message: 'Unsupported authorization event',
					code: AUTHORIZATION_FAILED$2,
					pageHtml: $.html()
				});
			}

			debug$4('auth with login & pass complete');

			if ($('form').length !== 0) {
				const { action } = parseFormField($);

				debug$4('url grant access', action);

				response = await this.fetch(action, {
					method: 'POST'
				});
			} else {
				const locations = $.html().match(FIND_LOCATION_HREF_RE);

				if (locations === null) {
					throw new AuthError({
						message: 'Could not log in',
						code: AUTHORIZATION_FAILED$2,
						pageHtml: $.html()
					});
				}

				const location = locations[1].replace('&cancel=1', '');

				debug$4('url grant access', location);

				response = await this.fetch(location, {
					method: 'POST'
				});
			}
		}
	}

	/**
	 * Process form auth
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	async processAuthForm(response, $) {
		debug$4('process login handle');

		if (this.captchaValidate !== null) {
			this.captchaValidate.reject(new AuthError({
				message: 'Incorrect captcha code',
				code: FAILED_PASSED_CAPTCHA$2,
				pageHtml: $.html()
			}));

			this.captchaValidate = null;

			this.captchaAttempts += 1;
		}

		if (this.captchaAttempts > CAPTCHA_ATTEMPTS$1) {
			throw new AuthError({
				message: 'Maximum attempts passage captcha',
				code: FAILED_PASSED_CAPTCHA$2
			});
		}

		const { login, password, phone } = this;

		const { action, fields } = parseFormField($);

		fields.email = login || phone;
		fields.pass = password;

		if ('captcha_sid' in fields) {
			const src = $('.oauth_captcha').attr('src') || $('#captcha').attr('src');

			const { key, validate } = await this.vk.callbackService.processingCaptcha({
				type: captchaTypes.IMPLICIT_FLOW_AUTH,
				sid: fields.captcha_sid,
				src
			});

			this.captchaValidate = validate;

			fields.captcha_key = key;
		}

		debug$4('Fields', fields);

		const url = new URL$3(action);

		url.searchParams.set('utf8', 1);

		const pageResponse = await this.fetch(url, {
			method: 'POST',
			body: new URLSearchParams$3(fields)
		});

		return pageResponse;
	}

	/**
	 * Process two-factor form
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	async processTwoFactorForm(response, $) {
		debug$4('process two-factor handle');

		if (this.twoFactorValidate !== null) {
			this.twoFactorValidate.reject(new AuthError({
				message: 'Incorrect two-factor code',
				code: FAILED_PASSED_TWO_FACTOR$2,
				pageHtml: $.html()
			}));

			this.twoFactorAttempts += 1;
		}

		if (this.twoFactorAttempts >= TWO_FACTOR_ATTEMPTS$2) {
			throw new AuthError({
				message: 'Failed passed two-factor authentication',
				code: FAILED_PASSED_TWO_FACTOR$2
			});
		}

		const { action, fields } = parseFormField($);

		const { code, validate } = await this.vk.callbackService.processingTwoFactor({});

		fields.code = code;

		try {
			const url = getFullURL(action, response);

			response = await this.fetch(url, {
				method: 'POST',
				body: new URLSearchParams$3(fields)
			});

			return response;
		} catch (error) {
			validate.reject(error);

			throw error;
		}
	}

	/**
	 * Process security form
	 *
	 * @param {Response} response
	 * @param {Cheerio}  $
	 *
	 * @return {Promise<Response>}
	 */
	async processSecurityForm(response, $) {
		debug$4('process security form');

		const { login, phone } = this;

		let number;
		if (phone !== null) {
			number = phone;
		} else if (login !== null && !login.includes('@')) {
			number = login;
		} else {
			throw new AuthError({
				message: 'Missing phone number in the phone or login field',
				code: INVALID_PHONE_NUMBER$2,
				pageHtml: $.html()
			});
		}

		number = String(number).trim().replace(REPLACE_PREFIX_RE, '');

		const $field = $('.field_prefix');

		const { length: prefix } = $field.first().text().trim().replace(REPLACE_PREFIX_RE, '');
		const { length: postfix } = $field.last().text().trim();

		const { action, fields } = parseFormField($);

		fields.code = number.slice(prefix, number.length - postfix);

		const url = getFullURL(action, response);

		response = await this.fetch(url, {
			method: 'POST',
			body: new URLSearchParams$3(fields)
		});

		if (response.url.includes(ACTION_SECURITY_CODE$2)) {
			throw new AuthError({
				message: 'Invalid phone number',
				code: INVALID_PHONE_NUMBER$2,
				pageHtml: $.html()
			});
		}

		return response;
	}
}

const { URL: URL$4, URLSearchParams: URLSearchParams$4 } = nodeUrl;

const debug$5 = createDebug('vk-io:auth:implicit-flow-user');

const { AUTHORIZATION_FAILED: AUTHORIZATION_FAILED$3 } = authErrors;

class ImplicitFlowUser extends ImplicitFlow {
	/**
	 * Returns permission page
	 *
	 * @return {Promise<Response>}
	 */
	getPermissionsPage() {
		const { appId } = this;
		let { scope } = this;

		if (scope === 'all' || scope === null) {
			scope = getAllUsersPermissions();
		} else if (typeof scope !== 'number') {
			scope = getUsersPermissionsByName(scope);
		}

		debug$5('auth scope %s', scope);

		const params = new URLSearchParams$4({
			redirect_uri: CALLBACK_BLANK,
			response_type: 'token',
			display: 'page',
			v: this.apiVersion,
			client_id: appId,
			scope
		});

		const url = new URL$4(`https://oauth.vk.com/authorize?${params}`);

		return this.fetch(url, {
			method: 'GET'
		});
	}

	/**
	 * Starts authorization
	 *
	 * @return {Promise<Object>}
	 */
	async run() {
		const { response } = await super.run();

		let { hash } = new URL$4(response.url);

		if (hash.startsWith('#')) {
			hash = hash.substring(1);
		}

		const params = new URLSearchParams$4(hash);

		if (params.has('error')) {
			throw new AuthError({
				message: `Failed passed grant access: ${params.get('error_description') || 'Unknown error'}`,
				code: AUTHORIZATION_FAILED$3
			});
		}

		const user = params.get('user_id');
		const expires = params.get('expires_in');

		return {
			email: params.get('email'),
			user: user !== null
				? Number(user)
				: null,

			token: params.get('access_token'),
			expires: expires !== null
				? Number(expires)
				: null
		};
	}
}

const { URL: URL$5, URLSearchParams: URLSearchParams$5 } = nodeUrl;

const debug$6 = createDebug('vk-io:auth:implicit-flow-user');

const { AUTHORIZATION_FAILED: AUTHORIZATION_FAILED$4 } = authErrors;

class ImplicitFlowGroups extends ImplicitFlow {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} options
	 */
	constructor(vk, options) {
		super(vk, options);

		let { groups = null } = options;

		if (groups === null) {
			throw new VKError({
				message: 'Groups list must have'
			});
		}

		if (!Array.isArray(groups)) {
			groups = [groups];
		}

		this.groups = groups.map((group) => {
			if (typeof group !== 'number') {
				group = Number(group);
			}

			if (group < 0) {
				group = -group;
			}

			return group;
		});
	}

	/**
	 * Returns permission page
	 *
	 * @param {Array} groups
	 *
	 * @return {Promise<Response>}
	 */
	getPermissionsPage() {
		const { appId } = this;
		let { scope } = this;

		if (scope === 'all' || scope === null) {
			scope = getAllGroupsPermissions();
		} else if (typeof scope !== 'number') {
			scope = getGroupsPermissionsByName(scope);
		}

		debug$6('auth scope %s', scope);

		const params = new URLSearchParams$5({
			group_ids: this.groups.join(','),
			redirect_uri: CALLBACK_BLANK,
			response_type: 'token',
			display: 'page',
			v: this.apiVersion,
			client_id: appId,
			scope
		});

		const url = new URL$5(`https://oauth.vk.com/authorize?${params}`);

		return this.fetch(url, {
			method: 'GET'
		});
	}

	/**
	 * Starts authorization
	 *
	 * @return {Promise<Array>}
	 */
	async run() {
		const { response } = await super.run();

		let { hash } = new URL$5(response.url);

		if (hash.startsWith('#')) {
			hash = hash.substring(1);
		}

		const params = new URLSearchParams$5(hash);

		if (params.has('error')) {
			throw new AuthError({
				message: `Failed passed grant access: ${params.get('error_description') || 'Unknown error'}`,
				code: AUTHORIZATION_FAILED$4
			});
		}

		let expires = params.get('expires_in');

		if (expires !== null) {
			expires = Number(expires);
		}

		const tokens = [];

		for (const [name, value] of params) {
			if (!name.startsWith('access_token_')) {
				continue;
			}

			/* Example group access_token_XXXXX */
			const { 2: group } = name.split('_');

			tokens.push({
				group: Number(group),
				token: value,
				expires
			});
		}

		return tokens;
	}
}

const { inspect: inspect$2 } = nodeUtil;
const { createHash } = nodeCrypto;

const openAPIParams = [
	'expire',
	'secret',
	'mid',
	'sid',
	'sig'
];

class Auth {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'Auth';
	}

	/**
	 * Standalone authorization with login & password
	 *
	 * @return {ImplicitFlowUser}
	 */
	implicitFlowUser(options = {}) {
		return new ImplicitFlowUser(this.vk, options);
	}

	/**
	 * Standalone authorization with login & password for group
	 *
	 * @param {*}  groups
	 * @param {Object} options
	 *
	 * @return {ImplicitFlowGroup}
	 */
	implicitFlowGroups(groups, options = {}) {
		return new ImplicitFlowGroups(this.vk, { ...options, groups });
	}

	/**
	 * Direct authorization with login & login in user application
	 *
	 * @return {DirectAuth}
	 */
	direct() {
		const { appId, appSecret } = this.vk.options;

		return new DirectAuth(this.vk, { appId, appSecret });
	}

	/**
	 * Direct authorization with login & login in android application
	 *
	 * @return {DirectAuth}
	 */
	androidApp() {
		return new DirectAuth(this.vk, {
			appId: 2274003,
			appSecret: 'hHbZxrka2uZ6jB1inYsH'
		});
	}

	/**
	 * Direct authorization with login & login in windows application
	 *
	 * @return {DirectAuth}
	 */
	windowsApp() {
		return new DirectAuth(this.vk, {
			appId: 3697615,
			appSecret: 'AlVXZFMUqyrnABp8ncuU'
		});
	}

	/**
	 * Direct authorization with login & login in windows phone application
	 *
	 * @return {DirectAuth}
	 */
	windowsPhoneApp() {
		return new DirectAuth(this.vk, {
			appId: 3502557,
			appSecret: 'PEObAuQi6KloPM4T30DV'
		});
	}

	/**
	 * Direct authorization with login & login in iphone application
	 *
	 * @return {DirectAuth}
	 */
	iphoneApp() {
		return new DirectAuth(this.vk, {
			appId: 3140623,
			appSecret: 'VeWdmVclDCtn6ihuP1nt'
		});
	}

	/**
	 * Direct authorization with login & login in ipad application
	 *
	 * @return {DirectAuth}
	 */
	ipadApp() {
		return new DirectAuth(this.vk, {
			appId: 3682744,
			appSecret: 'mY6CDUswIVdJLCD3j15n'
		});
	}

	/**
	 * Verifies that the user is authorized through the Open API
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	async userAuthorizedThroughOpenAPI(params) {
		const paramsKeys = Object.keys(params)
			.filter(key => openAPIParams.includes(key))
			.sort();

		let sign = '';
		for (const key of paramsKeys) {
			if (key !== 'sig') {
				sign += `${key}=${params[key]}`;
			}
		}

		sign += this.vk.options.appSecret;
		sign = createHash('md5')
			.update(sign)
			.digest('hex');

		const isNotExpire = params.expire > (Date.now() / 1000);
		const authorized = params.sig === sign && isNotExpire;

		return { authorized };
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$2.custom](depth, options) {
		const { name } = this.constructor;

		return `${options.stylize(name, 'special')} {}`;
	}
}

const { Stream } = nodeStream;

/**
 * Check object is stream
 *
 * @param {Object} source
 *
 * @return {boolean}
 */
const isStream = source => (
	typeof source === 'object' && source instanceof Stream
);

/**
 * Copies object params to new object
 *
 * @param {Object} params
 * @param {Array}  properties
 *
 * @return {Object}
 */
const copyParams$1 = (params, properties) => {
	const copies = {};

	for (const property of properties) {
		if (property in params) {
			copies[property] = params[property];
		}
	}

	return copies;
};

/**
 * Returns buffer from stream in Promise
 *
 * @param {Stream} stream
 *
 * @returns {Promise<Buffer>}
 */
const streamToBuffer = stream => (
	new Promise((resolve, reject) => {
		const accum = [];

		stream.on('error', reject);

		stream.on('end', () => {
			resolve(Buffer.concat(accum));
		});

		stream.on('data', (chunk) => {
			accum.push(chunk);
		});
	})
);

const CRNL = '\r\n';
class MultipartStream extends SandwichStream {
    /**
     * Constructor
     */
    constructor(boundary) {
        super({
            head: `--${boundary}${CRNL}`,
            tail: `${CRNL}--${boundary}--`,
            separator: `${CRNL}--${boundary}${CRNL}`
        });
        this.boundary = boundary;
    }
    /**
     * Returns custom tag
     */
    get [Symbol.toStringTag]() {
        return 'MultipartStream';
    }
    /**
     * Adds part
     */
    addPart(part) {
        const partStream = new PassThrough();
        if ('headers' in part) {
            for (const [key, header] of Object.entries(part.headers)) {
                partStream.write(`${key}:${header}${CRNL}`);
            }
        }
        partStream.write(CRNL);
        if (isStream(part.body)) {
            part.body.pipe(partStream);
        }
        else {
            partStream.end(part.body);
        }
        this.add(partStream);
    }
    /**
     * Adds form data
     */
    append(field, body, { filename = null, headers = {} }) {
        let header = `form-data; name="${field}"`;
        if (filename !== null) {
            header += `; filename="${filename}"`;
        }
        this.addPart({
            headers: {
                ...headers,
                'Content-Disposition': header
            },
            body
        });
    }
}

const { inspect: inspect$3 } = nodeUtil;

class Attachment {
	/**
	 * Constructor
	 *
	 * @param {string} type
	 * @param {number} ownerId
	 * @param {number} id
	 * @param {string} accessKey
	 */
	constructor(type, ownerId, id, accessKey = null) {
		this.type = type;

		this.ownerId = Number(ownerId);
		this.id = Number(id);

		this.accessKey = accessKey;

		this.$filled = false;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}

	/**
	 * Parse attachment with string
	 *
	 * @param {string} attachment
	 *
	 * @return {Attachment}
	 */
	static fromString(attachment) {
		if (!parseAttachment.test(attachment)) {
			throw new VKError({
				message: 'Incorrect attachment'
			});
		}

		const [, type, ownerId, id, accessKey] = attachment.match(parseAttachment);

		return new Attachment(type, ownerId, id, accessKey);
	}

	/**
	 * Returns whether the attachment is filled
	 *
	 * @return {boolean}
	 */
	get isFilled() {
		return this.$filled;
	}

	/**
	 * Can be attached via string representation
	 *
	 * @returns {boolean}
	 */
	get canBeAttached() {
		return true;
	}

	/**
	 * Checks that the attachment is equivalent with object
	 *
	 * @param {Attachment} attachment
	 *
	 * @return {boolean}
	 */
	equals(attachment) {
		const target = !(attachment instanceof Attachment)
			? Attachment.fromString(attachment)
			: attachment;

		return (
			this.type === target.type
			&& this.ownerId === target.ownerId
			&& this.id === target.id
		);
	}

	/**
	 * Returns a string to attach a VK
	 *
	 * @return {string}
	 */
	toString() {
		const accessKey = this.accessKey !== null
			? `_${this.accessKey}`
			: '';

		return `${this.type}${this.ownerId}_${this.id}${accessKey}`;
	}

	/**
	 * Returns data for JSON
	 *
	 * @return {Object}
	 */
	toJSON() {
		return this[inspectCustomData]();
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return {
			payload: this.payload
		};
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$3.custom](depth, options) {
		const { name } = this.constructor;

		const customData = {
			id: this.id,
			ownerId: this.ownerId,
			accessKey: this.accessKey,

			...this[inspectCustomData]()
		};

		const payload = this.$filled
			? `${inspect$3(customData, { ...options, compact: false })}`
			: '{}';

		return `${options.stylize(name, 'special')} <${options.stylize(this, 'string')}> ${payload}`;
	}
}

const { inspect: inspect$4 } = nodeUtil;

class ExternalAttachment {
	/**
	 * Constructor
	 *
	 * @param {string} type
	 * @param {Object} payload
	 */
	constructor(type, payload) {
		this.type = type;
		this.payload = payload;

		this.$filled = false;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}

	/**
	 * Returns whether the attachment is filled
	 *
	 * @return {boolean}
	 */
	get isFilled() {
		return this.$filled;
	}


	/**
	 * Can be attached via string representation
	 *
	 * @returns {boolean}
	 */
	get canBeAttached() {
		return false;
	}

	/**
	 * Returns data for JSON
	 *
	 * @return {Object}
	 */
	toJSON() {
		return this[inspectCustomData]();
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return this.payload;
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$4.custom](depth, options) {
		const { name } = this.constructor;

		const customData = this[inspectCustomData]();

		const payload = inspect$4(customData, { ...options, compact: false });

		return `${options.stylize(name, 'special')} ${payload}`;
	}
}

const { POLL } = attachmentTypes;

class PollAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(POLL, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'answers' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [poll] = await this.vk.api.polls.getById({
			poll_id: this.id,
			owner_id: this.ownerId
		});

		this.payload = poll;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Checks whether the poll is anonymous
	 *
	 * @return {?boolean}
	 */
	get isAnonymous() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.anonymous;
	}

	/**
	 * Checks whether the poll allows multiple choice of answers
	 *
	 * @return {?boolean}
	 */
	get isMultiple() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.multiple;
	}

	/**
	 * Checks whether the poll is complete
	 *
	 * @return {?boolean}
	 */
	get isClosed() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.closed;
	}

	/**
	 * Check whether questions are attached to the discussion
	 *
	 * @return {?boolean}
	 */
	get isBoard() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.is_board;
	}

	/**
	 * Check if can edit the poll
	 *
	 * @return {?boolean}
	 */
	get isCanEdit() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.can_edit;
	}

	/**
	 * Check if can vote in the survey
	 *
	 * @return {?boolean}
	 */
	get isCanVote() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.can_vote;
	}

	/**
	 * Check if can complain about the poll
	 *
	 * @return {?boolean}
	 */
	get isCanReport() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.can_report;
	}

	/**
	 * Check if can share a survey
	 *
	 * @return {?boolean}
	 */
	get isCanShare() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.can_share;
	}

	/**
	 * Returns the ID of the poll author
	 *
	 * @return {?number}
	 */
	get authorId() {
		return this.payload.author_id || null;
	}

	/**
	 * Returns the question text
	 *
	 * @return {?string}
	 */
	get question() {
		return this.payload.question || null;
	}

	/**
	 * Returns the date when this poll was created
	 *
	 * @return {?number}
	 */
	get createdAt() {
		return this.payload.created || null;
	}

	/**
	 * Returns the end date of the poll in Unixtime. 0, if the poll is unlimited
	 *
	 * @return {?number}
	 */
	get endedAt() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.end_date;
	}

	/**
	 * Returns the number of votes
	 *
	 * @return {?number}
	 */
	get votes() {
		return this.payload.votes || null;
	}

	/**
	 * Returns the identifiers of the response options selected by the current user
	 *
	 * @return {?number[]}
	 */
	get answerIds() {
		return this.payload.answer_ids || null;
	}

	/**
	 * Returns the identifiers of 3 friends who voted in the poll
	 *
	 * @return {?Object[]}
	 */
	get friends() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.friends || [];
	}

	/**
	 * Returns the information about the options for the answer
	 *
	 * @return {?Object[]}
	 */
	get answers() {
		return this.payload.answers || null;
	}

	/**
	 * Returns the poll snippet background
	 *
	 * @return {?Object}
	 */
	get background() {
		return this.payload.background || null;
	}

	/**
	 * Returns a photo - the poll snippet background
	 *
	 * @return {?Object}
	 */
	get photo() {
		return this.payload.photo || null;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'authorId',
			'question',
			'createdAt',
			'endedAt',
			'votes',
			'answerIds',
			'friends',
			'answers',
			'background',
			'photo'
		]);
	}
}

const { GIFT } = attachmentTypes;

class GiftAttachment extends ExternalAttachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(GIFT, payload);

		this.vk = vk;
	}

	/**
	 * Returns the identifier gift
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.id;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return {
			id: this.id
		};
	}
}

// eslint-disable-next-line import/no-cycle

const attachmentsTypes = {
	[attachmentTypes.POLL]: () => PollAttachment,
	[attachmentTypes.GIFT]: () => GiftAttachment,
	[attachmentTypes.WALL]: () => WallAttachment,
	[attachmentTypes.LINK]: () => LinkAttachment,
	[attachmentTypes.PHOTO]: () => PhotoAttachment,
	[attachmentTypes.AUDIO]: () => AudioAttachment,
	[attachmentTypes.VIDEO]: () => VideoAttachment,
	[attachmentTypes.DOCUMENT]: () => DocumentAttachment,
	[attachmentTypes.MARKET]: () => MarketAttachment,
	[attachmentTypes.STICKER]: () => StickerAttachment,
	[attachmentTypes.GRAFFITI]: () => GraffitiAttachment,
	[attachmentTypes.WALL_REPLY]: () => WallReplyAttachment,
	[attachmentTypes.MARKET_ALBUM]: () => MarketAlbumAttachment,
	[attachmentTypes.AUDIO_MESSAGE]: () => AudioMessageAttachment
};

/**
 * Transform raw attachments to wrapper
 *
 * @param {Object[]} attachments
 * @param {VK}       vk
 *
 * @return {Object[]}
 */
// eslint-disable-next-line import/prefer-default-export
const transformAttachments = (attachments = [], vk) => (
	attachments
		.map((item) => {
			const { type } = item;

			const attachment = attachmentsTypes[type];

			return attachment
				? new (attachment())(item[type], vk)
				: false;
		})
		.filter(Boolean)
);

const { WALL } = attachmentTypes;

const kAttachments = Symbol('attachments');
const kCopyHistoryAttachments = Symbol('copyHistoryAttachments');

class WallAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(WALL, payload.to_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'date' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [post] = await this.vk.api.wall.getById({
			posts: `${this.ownerId}_${this.id}`,
			extended: 0
		});

		this.payload = post;

		this[kAttachments] = null;
		this[kCopyHistoryAttachments] = null;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Checks has comments
	 *
	 * @return {?boolean}
	 */
	get hasComments() {
		if (!this.$filled) {
			return null;
		}

		const { commentsCount } = this;

		return commentsCount !== null
			? commentsCount > 0
			: null;
	}

	/**
	 * Checks has ads in post
	 *
	 * @return {?boolean}
	 */
	get hasAds() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.marked_as_ads);
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Checks has this user reposted
	 *
	 * @return {?boolean}
	 */
	get hasUserReposted() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.reposts.user_reposted);
	}

	/**
	 * Checks has this user likes
	 *
	 * @return {?boolean}
	 */
	get hasUserLike() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.user_likes);
	}

	/**
	 * Checks can the current user comment on the entry
	 *
	 * @return {?boolean}
	 */
	get isCanUserCommented() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.comments.can_post);
	}

	/**
	 * Checks if a community can comment on a post
	 *
	 * @return {?boolean}
	 */
	get isCanGroupsCommented() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.comments.groups_can_post);
	}

	/**
	 * Checks if you can comment on a post
	 *
	 * @return {?boolean}
	 */
	get isCanCommented() {
		return this.isCanUserCommented() || this.isCanGroupsCommented();
	}

	/**
	 * Checks if a user can close on a comments
	 *
	 * @return {?boolean}
	 */
	get isCanCloseComments() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.comments.can_close);
	}

	/**
	 * Checks if a user can open on a comments
	 *
	 * @return {?boolean}
	 */
	get isCanOpenComments() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.comments.can_open);
	}

	/**
	 * Checks whether the current user can like the record
	 *
	 * @return {?boolean}
	 */
	get isCanLike() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.likes.can_like);
	}

	/**
	 * hecks whether the current user can repost the record
	 *
	 * @return {?boolean}
	 */
	get isCanReposted() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.likes.can_publish);
	}

	/**
	 * Checks is can this user pin post
	 *
	 * @return {?boolean}
	 */
	get isCanPin() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.can_pin);
	}

	/**
	 * Checks is can this user delete post
	 *
	 * @return {?boolean}
	 */
	get isCanDelete() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.can_delete);
	}

	/**
	 * Checks is can this user edit post
	 *
	 * @return {?boolean}
	 */
	get isCanEdit() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.can_edit);
	}

	/**
	 * Checks is can this user edit post
	 *
	 * @return {?boolean}
	 */
	get isPinned() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.is_pinned);
	}

	/**
	 * Checks is post created only by friends
	 *
	 * @return {?boolean}
	 */
	get isFriendsOnly() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.friends_only);
	}

	/**
	 * Checks is bookmarked current user
	 *
	 * @return {?boolean}
	 */
	get isFavorited() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.is_favorite);
	}

	/**
	 * Returns the identifier author
	 *
	 * @return {?number}
	 */
	get authorId() {
		return this.payload.from_id || null;
	}

	/**
	 * Returns the administrator identifier that posted the entry
	 *
	 * @return {?number}
	 */
	get createdUserId() {
		return this.payload.created_by || null;
	}

	/**
	 * The identifier of the record owner, in response to which the current
	 *
	 * @return {?number}
	 */
	get replyOwnerId() {
		return this.payload.reply_owner_id || null;
	}

	/**
	 * The identifier of the record in response to which the current one was left.
	 *
	 * @return {?number}
	 */
	get replyPostId() {
		return this.payload.reply_post_id || null;
	}

	/**
	 * Returns author identifier if the entry was published
	 * on behalf of the community and signed by the user
	 *
	 * @return {?number}
	 */
	get signerId() {
		return this.payload.signer_id || null;
	}

	/**
	 * Returns the date when this post was created
	 *
	 * @return {?number}
	 */
	get createdAt() {
		return this.payload.date || null;
	}

	/**
	 * Returns the post type
	 *
	 * @return {?string}
	 */
	get postType() {
		return this.payload.post_type || null;
	}

	/**
	 * Returns the post text
	 *
	 * @return {?string}
	 */
	get text() {
		return this.payload.text || null;
	}

	/**
	 * Returns the number of record views
	 *
	 * @return {?number}
	 */
	get viewsCount() {
		if (!this.$filled) {
			return null;
		}

		return 'views' in this.payload
			? this.payload.views.count
			: null;
	}

	/**
	 * Returns the likes count
	 *
	 * @return {?number}
	 */
	get likesCount() {
		if (!this.$filled) {
			return null;
		}

		return 'likes' in this.payload
			? this.payload.likes.count
			: null;
	}

	/**
	 * Returns the reposts count
	 *
	 * @return {?number}
	 */
	get repostsCount() {
		if (!this.$filled) {
			return null;
		}

		return 'reposts' in this.payload
			? this.payload.reposts.count
			: null;
	}

	/**
	 * Returns the comments count
	 *
	 * @return {?number}
	 */
	get commentsCount() {
		if (!this.$filled) {
			return null;
		}

		return 'comments' in this.payload
			? this.payload.comments.count
			: null;
	}

	/**
	 * Returns the likes info
	 *
	 * @return {?Object}
	 */
	get likes() {
		return this.payload.likes || null;
	}

	/**
	 * Returns the post source
	 *
	 * @return {?Object}
	 */
	get postSource() {
		return this.payload.post_source || null;
	}

	/**
	 * Returns the geo location
	 *
	 * @return {?Object}
	 */
	get geo() {
		return this.payload.geo || null;
	}

	/**
	 * Returns the history of reposts for post
	 *
	 * @return {WallAttachment[]}
	 */
	get copyHistory() {
		if (!this[kCopyHistoryAttachments]) {
			this[kCopyHistoryAttachments] = this.payload.copy_history
				? this.payload.copy_history.map(history => new WallAttachment(history, this.vk))
				: [];
		}

		return this[kCopyHistoryAttachments];
	}

	/**
	 * Returns the attachments
	 */
	get attachments() {
		if (!this[kAttachments]) {
			this[kAttachments] = transformAttachments(this.payload.attachments || [], this.vk);
		}

		return this[kAttachments];
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'authorId',
			'createdUserId',
			'replyOwnerId',
			'replyPostId',
			'signerId',
			'createdAt',
			'postType',
			'text',
			'viewsCount',
			'likesCount',
			'repostsCount',
			'commentsCount',
			'likes',
			'postSource',
			'geo',
			'copyHistory',
			'attachments'
		]);
	}
}

const { PHOTO } = attachmentTypes;

const SMALL_SIZES = ['m', 's'];
const MEDIUM_SIZES = ['y', 'r', 'q', 'p', ...SMALL_SIZES];
const LARGE_SIZES = ['w', 'z', ...MEDIUM_SIZES];

class PhotoAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(PHOTO, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'album_id' in payload && 'date' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [photo] = await this.vk.api.photos.getById({
			photos: `${this.ownerId}_${this.id}`,
			extended: 0
		});

		this.payload = photo;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Returns the ID of the user who uploaded the image
	 *
	 * @return {?number}
	 */
	get userId() {
		return this.payload.user_id || null;
	}

	/**
	 * Returns the ID of the album
	 *
	 * @return {?number}
	 */
	get albumId() {
		return this.payload.album_id || null;
	}

	/**
	 * Returns the photo text
	 *
	 * @return {?string}
	 */
	get text() {
		return this.payload.text || null;
	}

	/**
	 * Returns the date when this photo was created
	 *
	 * @return {?number}
	 */
	get createdAt() {
		return this.payload.date || null;
	}

	/**
	 * Returns the photo height
	 *
	 * @return {?number}
	 */
	get height() {
		return this.payload.height || null;
	}

	/**
	 * Returns the photo width
	 *
	 * @return {?number}
	 */
	get width() {
		return this.payload.width || null;
	}

	/**
	 * Returns the URL of a small photo
	 * (130 or 75)
	 *
	 * @return {?string}
	 */
	get smallPhoto() {
		if (!this.$filled) {
			return null;
		}

		const [size] = this.getSizes(SMALL_SIZES);

		return size.url;
	}

	/**
	 * Returns the URL of a medium photo
	 * (807 or 604 or less)
	 *
	 * @return {?string}
	 */
	get mediumPhoto() {
		if (!this.$filled) {
			return null;
		}

		const [size] = this.getSizes(MEDIUM_SIZES);

		return size.url;
	}

	/**
	 * Returns the URL of a large photo
	 * (2560 or 1280 or less)
	 *
	 * @return {?string}
	 */
	get largePhoto() {
		if (!this.$filled) {
			return null;
		}

		const [size] = this.getSizes(LARGE_SIZES);

		return size.url;
	}

	/**
	 * Returns the sizes
	 *
	 * @return {?Object[]}
	 */
	get sizes() {
		return this.payload.sizes || null;
	}

	/**
	 * Returns the sizes of the required types
	 *
	 * @param {string[]} sizeTypes
	 *
	 * @return {Object[]}
	 */
	getSizes(sizeTypes) {
		const { sizes } = this;

		return sizeTypes
			.map(sizeType => (
				sizes.find(size => size.type === sizeType) || null
			))
			.filter(Boolean);
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'userId',
			'albumId',
			'text',
			'createdAt',
			'height',
			'width',
			'smallPhoto',
			'mediumPhoto',
			'largePhoto',
			'sizes'
		]);
	}
}

const { LINK } = attachmentTypes;

const kPhoto = Symbol('kPhoto');

class LinkAttachment extends ExternalAttachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(LINK, payload);

		this.vk = vk;
	}

	/**
	 * Checks for the presence of a photo in a link
	 *
	 * @return {boolean}
	 */
	get hasPhoto() {
		return this.attachments.length > 0;
	}

	/**
	 * Returns the title
	 *
	 * @return {string}
	 */
	get title() {
		return this.payload.title;
	}

	/**
	 * Returns the title
	 *
	 * @return {?string}
	 */
	get caption() {
		return this.payload.caption || null;
	}

	/**
	 * Returns the description
	 *
	 * @return {?string}
	 */
	get description() {
		return this.payload.description || null;
	}

	/**
	 * Returns the URL of the link
	 *
	 * @return {string}
	 */
	get url() {
		return this.payload.url;
	}

	/**
	 * Returns the product
	 *
	 * @return {?Object}
	 */
	get product() {
		return this.payload.product;
	}

	/**
	 * Returns the button
	 *
	 * @return {?Object}
	 */
	get button() {
		return this.payload.button || null;
	}

	/**
	 * Returns the photo
	 *
	 * @return {?PhotoAttachment}
	 */
	get photo() {
		if (!this[kPhoto]) {
			this[kPhoto] = this.payload.photo
				? new PhotoAttachment(this.payload.photo, this.vk)
				: null;
		}

		return this[kPhoto];
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'title',
			'caption',
			'description',
			'url',
			'product',
			'button',
			'photo'
		]);
	}
}

const { AUDIO } = attachmentTypes;

class AudioAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(AUDIO, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'duration' in payload && 'date' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [audio] = await this.vk.api.audio.getById({
			audios: `${this.ownerId}_${this.id}`
		});

		this.payload = audio;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Checks whether audio is in high quality
	 *
	 * @return {?boolean}
	 */
	get isHq() {
		const { is_hq: isHq } = this.payload;

		if (!isHq) {
			return null;
		}

		return isHq === 1;
	}

	/**
	 * Returns the ID of the lyric
	 *
	 * @return {?number}
	 */
	get lyricsId() {
		return this.payload.lyrics_id || null;
	}

	/**
	 * Returns the ID of the album
	 *
	 * @return {?number}
	 */
	get albumId() {
		return this.payload.album_id || null;
	}

	/**
	 * Returns the ID of the genre
	 *
	 * @return {?number}
	 */
	get genreId() {
		return this.payload.album_id || null;
	}

	/**
	 * Returns the title
	 *
	 * @return {?string}
	 */
	get title() {
		return this.payload.title || null;
	}

	/**
	 * Returns the artist
	 *
	 * @return {?string}
	 */
	get artist() {
		return this.payload.artist || null;
	}

	/**
	 * Returns the duration
	 *
	 * @return {?number}
	 */
	get duration() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.duration;
	}

	/**
	 * Returns the date object when this audio was created
	 *
	 * @return {?number}
	 */
	get createdAt() {
		return this.payload.date || null;
	}

	/**
	 * Returns the URL of the audio
	 *
	 * @return {?string}
	 */
	get url() {
		return this.payload.url || null;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'lyricsId',
			'albumId',
			'genreId',
			'title',
			'artist',
			'duration',
			'createdAt',
			'url'
		]);
	}
}

const { VIDEO } = attachmentTypes;

class VideoAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(VIDEO, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'date' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const { items } = await this.vk.api.video.get({
			videos: `${this.ownerId}_${this.id}`,
			extended: 0
		});

		const [video] = items;

		this.payload = video;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Checks whether the video is repeatable
	 *
	 * @return {?boolean}
	 */
	get isRepeat() {
		return this.checkBooleanInProperty('repeat');
	}

	/**
	 * Checks that the user can add a video to himself
	 *
	 * @return {?boolean}
	 */
	get isCanAdd() {
		return this.checkBooleanInProperty('can_add');
	}

	/**
	 * Checks if the user can edit the video
	 *
	 * @return {?boolean}
	 */
	get isCanEdit() {
		return this.checkBooleanInProperty('can_edit');
	}

	/**
	 * Checks whether the video is being processed
	 *
	 * @return {?boolean}
	 */
	get isProcessing() {
		return this.checkBooleanInProperty('processing');
	}

	/**
	 * Checks whether the video is a broadcast
	 *
	 * @return {?boolean}
	 */
	get isBroadcast() {
		return this.checkBooleanInProperty('live');
	}

	/**
	 * Checks whether the video is a broadcast
	 *
	 * @return {?boolean}
	 */
	get isUpcoming() {
		return this.checkBooleanInProperty('upcoming');
	}

	/**
	 * Checks is bookmarked current user
	 *
	 * @return {?boolean}
	 */
	get isFavorited() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.is_favorite);
	}


	/**
	 * Returns the title
	 *
	 * @return {?string}
	 */
	get title() {
		return this.payload.title || null;
	}

	/**
	 * Returns the description
	 *
	 * @return {?string}
	 */
	get description() {
		return this.payload.description || null;
	}

	/**
	 * Returns the duration
	 *
	 * @return {?number}
	 */
	get duration() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.duration;
	}

	/**
	 * Returns the date when this video was created
	 *
	 * @return {?number}
	 */
	get createdAt() {
		return this.payload.date || null;
	}

	/**
	 * Returns the date when this video was added
	 *
	 * @return {?Date}
	 */
	get addedAt() {
		return this.payload.adding_date || null;
	}

	/**
	 * Returns the count views
	 *
	 * @return {?number}
	 */
	get viewsCount() {
		return this.payload.views || null;
	}

	/**
	 * Returns the count comments
	 *
	 * @return {?number}
	 */
	get commentsCount() {
		return this.payload.comments || null;
	}

	/**
	 * Returns the URL of the page with the player
	 *
	 * @return {?string}
	 */
	get player() {
		return this.payload.player || null;
	}


	/**
	 * Returns the name of the platform (for video recordings added from external sites)
	 *
	 * @return {?string}
	 */
	get platformName() {
		return this.payload.platform || null;
	}

	/**
	 * Checks for a boolean value in the property
	 *
	 * @param {string} name
	 *
	 * @return {?boolean}
	 */
	checkBooleanInProperty(name) {
		const property = this.payload[name];

		if (typeof property !== 'number') {
			return null;
		}

		return property === 1;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'title',
			'description',
			'duration',
			'createdAt',
			'addedAt',
			'viewsCount',
			'commentsCount',
			'player',
			'platformName'
		]);
	}
}

const { MARKET } = attachmentTypes;

class MarketAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(MARKET, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'title' in payload && 'date' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [market] = await this.vk.api.market.getById({
			item_ids: `${this.ownerId}_${this.id}`,
			extended: 0
		});

		this.payload = market;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Checks is bookmarked current user
	 *
	 * @return {?boolean}
	 */
	get isFavorited() {
		if (!this.$filled) {
			return null;
		}

		return Boolean(this.payload.is_favorite);
	}
}

const { STICKER } = attachmentTypes;

class StickerAttachment extends ExternalAttachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(STICKER, payload);

		this.vk = vk;
	}

	/**
	 * Returns the identifier sticker
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.sticker_id;
	}

	/**
	 * Returns the identifier product
	 *
	 * @return {number}
	 */
	get productId() {
		return this.payload.product_id;
	}

	/**
	 * Returns the images sizes
	 *
	 * @return {Object[]}
	 */
	get images() {
		return this.payload.images || [];
	}

	/**
	 * Returns the images sizes with backgrounds
	 *
	 * @return {Object[]}
	 */
	get imagesWithBackground() {
		return this.payload.images_with_background || [];
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'id',
			'productId',
			'images',
			'imagesWithBackground'
		]);
	}
}

const { GRAFFITI } = attachmentTypes;

class GraffitiAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(GRAFFITI, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'url' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [document] = await this.vk.api.docs.getById({
			docs: `${this.ownerId}_${this.id}`
		});

		this.payload = document;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Returns the graffiti height
	 *
	 * @return {?number}
	 */
	get height() {
		return this.payload.height || null;
	}

	/**
	 * Returns the graffiti width
	 *
	 * @return {?number}
	 */
	get width() {
		return this.payload.width || null;
	}

	/**
	 * Returns the URL of the document
	 *
	 * @return {?string}
	 */
	get url() {
		return this.payload.url || null;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'height',
			'width',
			'url'
		]);
	}
}

const { DOCUMENT } = attachmentTypes;

/**
 * Types of documents
 *
 * @type {Map}
 */
const documentTypes = new Map([
	[1, 'text'],
	[2, 'archive'],
	[3, 'gif'],
	[4, 'image'],
	[5, 'audio'],
	[6, 'video'],
	[7, 'book'],
	[8, 'unknown']
]);

class DocumentAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(DOCUMENT, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'ext' in payload && 'date' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [document] = await this.vk.api.docs.getById({
			docs: `${this.ownerId}_${this.id}`
		});

		this.payload = document;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Checks if the document is a text
	 *
	 * @return {?boolean}
	 */
	get isText() {
		if (!this.$filled) {
			return null;
		}

		return this.typeId === 1;
	}

	/**
	 * Checks if the document is a archive
	 *
	 * @return {?boolean}
	 */
	get isArchive() {
		if (!this.$filled) {
			return null;
		}

		return this.typeId === 2;
	}

	/**
	 * Checks if the document is a gif file
	 *
	 * @return {?boolean}
	 */
	get isGif() {
		if (!this.$filled) {
			return null;
		}

		return this.typeId === 3;
	}

	/**
	 * Checks if the document is a image
	 *
	 * @return {?boolean}
	 */
	get isImage() {
		if (!this.$filled) {
			return null;
		}

		return this.typeId === 4;
	}

	/**
	 * Checks if the document is a graffiti
	 *
	 * @return {?boolean}
	 */
	get isGraffiti() {
		if (!this.$filled) {
			return null;
		}

		return this.hasPreviewProperty('graffiti');
	}

	/**
	 * Checks if the document is a audio
	 *
	 * @return {?boolean}
	 */
	get isAudio() {
		if (!this.$filled) {
			return null;
		}

		return this.typeId === 5;
	}

	/**
	 * Checks if the document is a voice
	 *
	 * @return {?boolean}
	 */
	get isVoice() {
		if (!this.$filled) {
			return null;
		}

		return this.hasPreviewProperty('audio_msg');
	}

	/**
	 * Checks if the document is a video
	 *
	 * @return {?boolean}
	 */
	get isVideo() {
		if (!this.$filled) {
			return null;
		}

		return this.typeId === 6;
	}

	/**
	 * Checks if the document is a book
	 *
	 * @return {?boolean}
	 */
	get isBook() {
		if (!this.$filled) {
			return null;
		}

		return this.typeId === 7;
	}

	/**
	 * Returns the document title
	 *
	 * @return {?string}
	 */
	get title() {
		return this.payload.title || null;
	}

	/**
	 * Returns the date when this document was created
	 *
	 * @return {?number}
	 */
	get createdAt() {
		return this.payload.date || null;
	}

	/**
	 * Returns the type identifier (1~8)
	 *
	 * @return {?number}
	 */
	get typeId() {
		return this.payload.type || null;
	}

	/**
	 * Returns the type name
	 *
	 * @return {?string}
	 */
	get typeName() {
		if (!this.$filled) {
			return null;
		}

		return documentTypes.get(this.typeId);
	}

	/**
	 * Returns the size in bytes
	 *
	 * @return {?number}
	 */
	get size() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.size;
	}

	/**
	 * Returns the extension
	 *
	 * @return {?string}
	 */
	get extension() {
		return this.payload.ext || null;
	}

	/**
	 * Returns the URL of the document
	 *
	 * @return {?string}
	 */
	get url() {
		return this.payload.url || null;
	}

	/**
	 * Returns the info to preview
	 *
	 * @return {?Object}
	 */
	get preview() {
		return this.payload.preview || null;
	}

	/**
	 * Checks for a property in preview
	 *
	 * @param {string} name
	 *
	 * @return {boolean}
	 */
	hasPreviewProperty(name) {
		const { preview } = this;

		if (preview === null) {
			return false;
		}

		return name in preview;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'title',
			'typeId',
			'typeName',
			'createdAt',
			'extension',
			'url'
		]);
	}
}

const { WALL_REPLY } = attachmentTypes;

class WallReplyAttachment extends ExternalAttachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(WALL_REPLY, payload);

		this.vk = vk;
	}
}

const { MARKET_ALBUM } = attachmentTypes;

class MarketAlbumAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(MARKET_ALBUM, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'title' in payload && 'updated_time' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [album] = await this.vk.api.market.getAlbumById({
			owner_id: this.ownerId,
			album_ids: this.id
		});

		this.payload = album;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}
}

const { AUDIO_MESSAGE } = attachmentTypes;

class AudioMessageAttachment extends Attachment {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {VK}     vk
	 */
	constructor(payload, vk) {
		super(AUDIO_MESSAGE, payload.owner_id, payload.id, payload.access_key);

		this.vk = vk;
		this.payload = payload;

		this.$filled = 'duration' in payload;
	}

	/**
	 * Load attachment payload
	 *
	 * @return {Promise}
	 */
	async loadAttachmentPayload() {
		if (this.$filled) {
			return;
		}

		const [document] = await this.vk.api.docs.getById({
			docs: `${this.ownerId}_${this.id}`
		});

		this.payload = document;

		if ('access_key' in this.payload) {
			this.accessKey = this.payload.access_key;
		}

		this.$filled = true;
	}

	/**
	 * Returns the duration of the audio message
	 *
	 * @return {?number}
	 */
	get duration() {
		if (!this.$filled) {
			return null;
		}

		return this.payload.duration;
	}

	/**
	 * Returns the waveform of the audio message
	 *
	 * @return {?number[]}
	 */
	get waveform() {
		return this.payload.waveform || null;
	}

	/**
	 * Returns the ogg URL of the audio message
	 *
	 * @return {?string}
	 */
	get oggUrl() {
		return this.payload.link_ogg || null;
	}

	/**
	 * Returns the mp3 URL of the audio message
	 *
	 * @return {?string}
	 */
	get mp3Url() {
		return this.payload.link_mp3 || null;
	}

	/**
	 * Returns the URL of the audio message
	 *
	 * @return {?string}
	 */
	get url() {
		return this.mp3Url || this.oggUrl;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		const payload = copyParams(this, [
			'duration',
			'waveform',
			'oggUrl',
			'mp3Url',
			'url'
		]);

		payload.waveform = `[...${this.waveform.length} elements]`;

		return payload;
	}
}

const { randomBytes } = nodeCrypto;
const { createReadStream } = nodeFs;
const { inspect: inspect$5, deprecate } = nodeUtil;

const {
	MISSING_PARAMETERS,
	NO_FILES_TO_UPLOAD,
	EXCEEDED_MAX_FILES,
	UNSUPPORTED_SOURCE_TYPE
} = uploadErrors;

const isURL = /^https?:\/\//i;

class Upload {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.graffiti = deprecate(
			params => (
				this.messageGraffiti(params)
			),
			'graffiti(params) is deprecated, use messageGraffiti(params) instead'
		);
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'Upload';
	}

	/**
	 * Uploading photos to an album
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<PhotoAttachment[]>}
	 */
	async photoAlbum(params) {
		const photos = await this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.photos.getUploadServer,
			serverParams: ['album_id', 'group_id'],

			saveFiles: this.vk.api.photos.save,
			saveParams: ['album_id', 'group_id', 'latitude', 'longitude', 'caption'],

			maxFiles: 5,
			attachmentType: 'photo'
		});

		return photos.map(photo => (
			new PhotoAttachment(photo, this.vk)
		));
	}

	/**
	 * Uploading photos to the wall
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<PhotoAttachment>}
	 */
	async wallPhoto(params) {
		const [photo] = await this.conduct({
			field: 'photo',
			params,

			getServer: this.vk.api.photos.getWallUploadServer,
			serverParams: ['group_id'],

			saveFiles: this.vk.api.photos.saveWallPhoto,
			saveParams: ['user_id', 'group_id', 'latitude', 'longitude', 'caption'],

			maxFiles: 1,
			attachmentType: 'photo'
		});

		return new PhotoAttachment(photo, this.vk);
	}

	/**
	 * Uploading the main photo of a user or community
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	ownerPhoto(params) {
		return this.conduct({
			field: 'photo',
			params,

			getServer: this.vk.api.photos.getOwnerPhotoUploadServer,
			serverParams: ['owner_id'],

			saveFiles: this.vk.api.photos.saveOwnerPhoto,

			maxFiles: 1,
			attachmentType: 'photo'
		});

		// {
		//   photo_hash: 'c8d43da5e1281b7aed6bb8f0c4f3ad69',
		//   photo_src: 'https://pp.userapi.com/c836429/v836429114/673f6/5VJB8GXtK88.jpg',
		//   photo_src_big: 'https://pp.userapi.com/c836429/v836429114/673f7/7fGvrJ1wOx0.jpg',
		//   photo_src_small: 'https://pp.userapi.com/c836429/v836429114/673f5/l5d1ASgyuxk.jpg',
		//   saved: 1,
		//   post_id: 3331
		// }
	}

	/**
	 * Uploading a photo to a private message
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<PhotoAttachment>}
	 */
	async messagePhoto(params) {
		const [photo] = await this.conduct({
			field: 'photo',
			params,

			getServer: this.vk.api.photos.getMessagesUploadServer,
			serverParams: ['peer_id'],

			saveFiles: this.vk.api.photos.saveMessagesPhoto,

			maxFiles: 1,
			attachmentType: 'photo'
		});

		return new PhotoAttachment(photo, this.vk);
	}

	/**
	 * Uploading the main photo for a chat
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	chatPhoto(params) {
		return this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.photos.getChatUploadServer,
			serverParams: ['chat_id', 'crop_x', 'crop_y', 'crop_width'],

			saveFiles: file => (
				this.vk.api.messages.setChatPhoto({ file })
			),

			maxFiles: 1,
			attachmentType: 'photo'
		});

		// {
		//   message_id: 3745390,
		//   chat: {
		//    id: 152,
		//    type: 'chat',
		//    title: '<Titile name>',
		//    admin_id: 335447860,
		//    users: [335447860,
		//      140192020,
		//      153711615,
		//      314650825,
		//      218747758,
		//      155944103,
		//      159737827,
		//      64299368,
		//      157534541,
		//      153608064,
		//      335540121,
		//      349609849,
		//      344184938,
		//      341178526,
		//      198210835,
		//      135446999,
		//      163850606,
		//      123640861,
		//      316216798,
		//      359118107,
		//      241235369,
		//      160213445,
		//      126624591,
		//      390221395,
		//      195624402,
		//      94955334,
		//      167302501,
		//      17516523,
		//      294583792,
		//      294869767,
		//      114281676,
		//      137762280,
		//      406076540,
		//      410605840,
		//      395646590,
		//      421554042,
		//      331599090,
		//      342269712
		//    ],
		//    photo_50: 'https://pp.userapi.com/c837624/v837624114/5d495/gLgv-JrVmkk.jpg',
		//    photo_100: 'https://pp.userapi.com/c837624/v837624114/5d494/VNp61I1yuCk.jpg',
		//    photo_200: 'https://pp.userapi.com/c837624/v837624114/5d492/lAoc_fAai2Q.jpg'
		//   }
		// }
	}

	/**
	 * Uploading a photo for a product
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<PhotoAttachment>}
	 */
	async marketPhoto(params) {
		const [photo] = await this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.photos.getMarketUploadServer,
			serverParams: ['group_id', 'main_photo', 'crop_x', 'crop_y', 'crop_width'],

			saveFiles: this.vk.api.photos.saveMarketPhoto,
			saveParams: ['group_id'],

			maxFiles: 1,
			attachmentType: 'photo'
		});

		return new PhotoAttachment(photo, this.vk);
	}

	/**
	 * Uploads a photo for the selection of goods
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<PhotoAttachment>}
	 */
	async marketAlbumPhoto(params) {
		const [photo] = await this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.photos.getMarketAlbumUploadServer,
			serverParams: ['group_id'],

			saveFiles: this.vk.api.photos.saveMarketAlbumPhoto,
			saveParams: ['group_id'],

			maxFiles: 1,
			attachmentType: 'photo'
		});

		return new PhotoAttachment(photo, this.vk);
	}

	/**
	 * Uploads audio
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<AudioAttachment>}
	 */
	async audio(params) {
		const audio = await this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.audio.getUploadServer,

			saveFiles: this.vk.api.audio.save,
			saveParams: ['title', 'artist'],

			maxFiles: 1,
			attachmentType: 'audio'
		});

		return new AudioAttachment(audio, this.vk);
	}

	/**
	 * Uploads video
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<VideoAttachment>}
	 */
	async video(params) {
		const save = await this.vk.api.video.save(copyParams$1(params, [
			'group_id',
			'album_id',
			'link',
			'name',
			'description',
			'is_private',
			'wallpost',
			'privacy_view',
			'privacy_comment',
			'no_comments',
			'repeat',
			'compression'
		]));

		save.id = save.video_id;

		if ('link' in params) {
			const response = await fetch(save.upload_url, {
				agent: this.vk.options.agent
			});

			await response.json();

			return new VideoAttachment(save, this.vk);
		}

		let { source } = params;

		if (typeof source !== 'object' || source.constructor !== Object) {
			source = {
				values: source
			};
		}

		if (!Array.isArray(source.values)) {
			source.values = [source.values];
		}

		const formData = await this.buildPayload({
			maxFiles: 1,
			field: 'video_file',
			attachmentType: 'video',
			values: source.values
		});

		const video = await this.upload(save.upload_url, {
			formData,
			forceBuffer: true,
			timeout: source.timeout
		});

		return new VideoAttachment({ ...save, ...video }, this.vk);
	}

	/**
	 * Uploads document
	 *
	 * @param {Object} params
	 * @param {Object} options
	 *
	 * @return {Promise<Object>}
	 */
	async conductDocument(params, { attachmentType = 'doc' }) {
		return this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.docs.getUploadServer,
			serverParams: ['type', 'group_id'],

			saveFiles: this.vk.api.docs.save,
			saveParams: ['title', 'tags'],

			maxFiles: 1,
			attachmentType
		});
	}

	/**
	 * Uploads document
	 *
	 * @param {Object} params
	 * @param {Object} options
	 *
	 * @return {Promise<DocumentAttachment>}
	 */
	async document(params) {
		const { doc: document } = await this.conductDocument(params, {
			attachmentType: 'doc'
		});

		return new DocumentAttachment(document, this.vk);
	}

	/**
	 * Uploads wall document
	 *
	 * @param {Object} params
	 * @param {Object} options
	 *
	 * @return {Promise<Object>}
	 */
	async conductWallDocument(params, { attachmentType = 'doc' } = {}) {
		return this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.docs.getWallUploadServer,
			serverParams: ['type', 'group_id'],

			saveFiles: this.vk.api.docs.save,
			saveParams: ['title', 'tags'],

			maxFiles: 1,
			attachmentType
		});
	}

	/**
	 * Uploads wall document
	 *
	 * @param {Object} params
	 * @param {Object} options
	 *
	 * @return {Promise<DocumentAttachment>}
	 */
	async wallDocument(params) {
		const { doc: document } = await this.conductWallDocument(params, {
			attachmentType: 'doc'
		});

		return new DocumentAttachment(document, this.vk);
	}

	/**
	 * Uploads wall document
	 *
	 * @param {Object} params
	 * @param {Object} options
	 *
	 * @return {Promise<Object>}
	 */
	async conductMessageDocument(params, { attachmentType = 'doc' } = {}) {
		return this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.docs.getMessagesUploadServer,
			serverParams: ['type', 'peer_id'],

			saveFiles: this.vk.api.docs.save,
			saveParams: ['title', 'tags'],

			maxFiles: 1,
			attachmentType
		});
	}

	/**
	 * Uploads message document
	 *
	 * @param {Object} params
	 * @param {Object} options
	 *
	 * @return {Promise<DocumentAttachment>}
	 */
	async messageDocument(params) {
		const { doc: document } = await this.conductMessageDocument(params, {
			attachmentType: 'doc'
		});

		return new DocumentAttachment(document, this.vk);
	}

	/**
	 * Uploads audio message
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<AudioMessageAttachment>}
	 */
	async audioMessage(params) {
		const { audio_message: audioMessage } = await this.conductMessageDocument(
			{
				...params,
				type: 'audio_message'
			},
			{
				attachmentType: 'audioMessage'
			}
		);

		const audioMessageAttachment = new AudioMessageAttachment(audioMessage, this.vk);

		return audioMessageAttachment;

		// { type: 'audio_message',
		// audio_message: {
		//   id: 484017542,
		//   owner_id: 195624402,
		//   duration: 48,
		//   waveform: [...],
		//   link_ogg:
		//   'https://psv4.userapi.com/c805324//u195624402/audiomsg/15734aa6bb.ogg',
		//   link_mp3:
		//   'https://psv4.userapi.com/c805324//u195624402/audiomsg/15734aa6bb.mp3',
		//   access_key: '295cc90411e6222db0' } }
	}

	/**
	 * Uploads graffiti in documents
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<GraffitiAttachment>}
	 */
	async documentGraffiti(params) {
		const { graffiti } = await this.conductDocument(
			{
				...params,
				type: 'graffiti'
			},
			{
				attachmentType: 'graffiti'
			}
		);

		const graffitiAttachment = new GraffitiAttachment(graffiti, this.vk);

		return graffitiAttachment;
	}

	/**
	 * Uploads graffiti in messages
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<GraffitiAttachment>}
	 */
	async messageGraffiti(params) {
		const { graffiti } = await this.conductMessageDocument(
			{
				...params,
				type: 'graffiti'
			},
			{
				attachmentType: 'graffiti'
			}
		);

		const graffitiAttachment = new GraffitiAttachment(graffiti, this.vk);

		return graffitiAttachment;
	}

	/**
	 * Uploads community cover
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	groupCover(params) {
		return this.conduct({
			field: 'photo',
			params,

			getServer: this.vk.api.photos.getOwnerCoverPhotoUploadServer,
			serverParams: ['group_id', 'crop_x', 'crop_y', 'crop_x2', 'crop_y2'],

			saveFiles: this.vk.api.photos.saveOwnerCoverPhoto,

			maxFiles: 1,
			attachmentType: 'photo'
		});

		// {
		//  images: [
		//    {
		//      url: 'https://cs7056.userapi.com/c639526/v639526192/46404/r-1Nhr-Dktc.jpg',
		//      width: 200,
		//      height: 50
		//    },
		//    {
		//      url: 'https://cs7056.userapi.com/c639526/v639526192/46403/oDB9tAgtUrQ.jpg',
		//      width: 400,
		//      height: 101
		//    },
		//    {
		//      url: 'https://cs7056.userapi.com/c639526/v639526192/46400/gLwCTmDEPXY.jpg',
		//      width: 795,
		//      height: 200
		//    },
		//    {
		//      url: 'https://cs7056.userapi.com/c639526/v639526192/46402/w2ucyq8zwF8.jpg',
		//      width: 1080,
		//      height: 272
		//    },
		//    {
		//      url: 'https://cs7056.userapi.com/c639526/v639526192/46401/YTmN89yMaU0.jpg',
		//      width: 1590,
		//      height: 400
		//    }
		//  ]
		// }
	}

	/**
	 * Uploads photo stories
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	storiesPhoto(params) {
		return this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.stories.getPhotoUploadServer,
			serverParams: [
				'add_to_news',
				'user_ids',
				'reply_to_story',
				'link_text',
				'link_url',
				'group_id',
				'attach_access_key'
			],

			saveFiles: save => save,

			maxFiles: 1,
			attachmentType: 'photo'
		});
	}

	/**
	 * Uploads video stories
	 *
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	storiesVideo(params) {
		return this.conduct({
			field: 'video_file',
			params,

			getServer: this.vk.api.stories.getVideoUploadServer,
			serverParams: [
				'add_to_news',
				'user_ids',
				'reply_to_story',
				'link_text',
				'link_url',
				'group_id'
			],

			saveFiles: save => save,

			maxFiles: 1,
			attachmentType: 'video',

			forceBuffer: true
		});
	}

	/**
	 * Uploads poll photo
	 *
	 * @param {Object}
	 *
	 * @return {Promise<Object>}
	 */
	pollPhoto(params) {
		return this.conduct({
			field: 'file',
			params,

			getServer: this.vk.api.polls.getPhotoUploadServer,
			serverParams: ['owner_id'],

			saveFiles: this.vk.api.polls.savePhoto,

			maxFiles: 1,
			attachmentType: 'photo'
		});
	}

	/**
	 * Behavior for the upload method
	 *
	 * @param {Object} conduct
	 * @property [field]          Field name
	 * @property [params]         Upload params
	 *
	 * @property [getServer]      Get server functions
	 * @property [serverParams]   Copies server params
	 *
	 * @property [saveFiles]      Save files functions
	 * @property [saveParams]     Copies save params
	 *
	 * @property [maxFiles]       Max uploaded files for one request
	 * @property [attachmentType] Attachment type
	 *
	 * @return {Promise<Object>}
	 */
	async conduct({
		field,
		params,

		getServer,
		serverParams = [],

		saveFiles,
		saveParams = [],

		maxFiles = 1,
		attachmentType,

		forceBuffer = false
	}) {
		if (!params || !params.source) {
			throw new UploadError({
				message: 'Missing upload params',
				code: MISSING_PARAMETERS
			});
		}

		let { source } = params;

		if (
			typeof source !== 'object'
			|| source.constructor !== Object
			|| source.value !== undefined) {
			source = {
				values: source
			};
		}

		if (!Array.isArray(source.values)) {
			source.values = [source.values];
		}

		if ('uploadUrl' in source) {
			getServer = () => ({
				upload_url: source.uploadUrl
			});
		}

		const { length: valuesLength } = source.values;

		if (valuesLength === 0) {
			throw new UploadError({
				message: 'No files to upload',
				code: NO_FILES_TO_UPLOAD
			});
		}

		if (valuesLength > maxFiles) {
			throw new UploadError({
				message: 'The number of files uploaded has exceeded',
				code: EXCEEDED_MAX_FILES
			});
		}

		const [{ upload_url: url }, formData] = await Promise.all([
			getServer(copyParams$1(params, serverParams)),
			this.buildPayload({
				field,
				values: source.values,
				maxFiles,
				attachmentType
			})
		]);

		const uploaded = await this.upload(url, {
			formData,
			forceBuffer,
			timeout: source.timeout
		});

		if (typeof uploaded !== 'object') {
			const response = await saveFiles(uploaded);

			return response;
		}

		const response = await saveFiles({
			...copyParams$1(params, saveParams),
			...uploaded
		});

		return response;
	}

	/**
	 * Building form data
	 *
	 * @param {Object} payload
	 *
	 * @return {Promise}
	 */
	async buildPayload({
		field,
		values,
		maxFiles,
		attachmentType
	}) {
		const boundary = randomBytes(32).toString('hex');
		const formData = new MultipartStream(boundary);

		const isMultipart = maxFiles > 1;

		const tasks = values
			.map(value => (
				typeof value === 'object' && value.constructor === Object
					? value
					: { value }
			))
			.map(async (
				{
					value,
					filename,
					contentType = null
				},
				i
			) => {
				if (typeof value === 'string') {
					if (isURL.test(value)) {
						const response = await fetch(value);

						value = response.body;
					} else {
						value = createReadStream(value);
					}
				}

				if (!filename) {
					filename = `file${i}.${defaultExtensions[attachmentType] || 'dat'}`;
				}

				if (isStream(value) || Buffer.isBuffer(value)) {
					const name = isMultipart
						? field + (i + 1)
						: field;

					const headers = {
						'Content-Type': contentType === null
							? defaultContentTypes[attachmentType]
							: contentType
					};

					return formData.append(name, value, { filename, headers });
				}

				throw new UploadError({
					message: 'Unsupported source type',
					code: UNSUPPORTED_SOURCE_TYPE
				});
			});

		await Promise.all(tasks);

		return formData;
	}

	/**
	 * Upload form data
	 *
	 * @param {URL|string} url
	 * @param {Object}     options
	 *
	 * @return {Promise<Object>}
	 */
	async upload(url, { formData, timeout, forceBuffer }) {
		const { agent, uploadTimeout } = this.vk.options;

		const body = forceBuffer
			? await streamToBuffer(formData)
			: formData;

		let response = await fetch(url, {
			agent,
			compress: false,
			method: 'POST',
			timeout: timeout || uploadTimeout,
			headers: {
				Connection: 'keep-alive',
				'Content-Type': `multipart/form-data; boundary=${formData.boundary}`
			},
			body
		});

		if (!response.ok) {
			throw new Error(response.statusText);
		}

		response = await response.json();

		return response.response !== undefined
			? response.response
			: response;
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$5.custom](depth, options) {
		const { name } = this.constructor;

		return `${options.stylize(name, 'special')} {}`;
	}
}

const unespaceOffset = /"offset":"(\w+)"/g;

var getExecuteCode = ({ method, params, parallelCount }) => {
	const methodCode = getExecuteMethod(method, {
		...params,

		offset: 'offset'
	});

	const code = `
		var total = parseInt(Args.total);
		var offset = parseInt(Args.offset);
		var received = parseInt(Args.received);

		var proceed = total == 0 || received < total;

		var i = 0, items = [], profiles = [], groups = [], result, length;

		while (i < ${parallelCount} && proceed) {
			result = ${methodCode};
			length = result.items.length;

			if (total == 0 || total > result.count) {
				total = result.count;
			}

			items = items + result.items;
			if (result.profiles)
				profiles = profiles + result.profiles;
			if (result.groups)
				groups = groups + result.groups;

			offset = offset + length;
			received = received + length;

			proceed = received < total;
			i = i + 1;
		}

		return {
			total: total,
			items: items.splice(0, total),
			profiles: profiles.splice(0, total),
			groups: groups.splice(0, total)
		};
	`;

	return code.replace(unespaceOffset, '"offset":$1');
};

const { inspect: inspect$6 } = nodeUtil;
const { Readable } = nodeStream;

const debug$7 = createDebug('vk-io:collect:stream');

const { APP_TOKEN_NOT_VALID, RESPONSE_SIZE_TOO_BIG } = apiErrors;

const { EXECUTE_ERROR } = collectErrors;

class CollectStream extends Readable {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk, {
		options,
		method,
		limit,
		max = null
	}) {
		super({
			objectMode: true
		});

		this.vk = vk;

		const {
			parallelCount = 25,
			count = null,
			offset = 0,
			...params
		} = options;

		this.method = method;
		this.params = {
			...params,

			count: limit
		};

		if (parallelCount < 1 || parallelCount > 25) {
			throw new RangeError('The number of parallel calls can be between 1 and 25');
		}

		this.parallelCount = parallelCount;

		const hasMax = max !== null;
		const hasCount = count !== null;

		if ((hasCount && hasMax && count > max) || (hasMax && !hasCount)) {
			this.total = max;
		} else {
			this.total = count;
		}

		this.offset = offset;
		this.skipOffset = offset;

		this.received = 0;

		this.attempts = 0;
		this.promise = null;
		this.supportExecute = true;

		this.code = getExecuteCode({
			params: this.params,
			parallelCount,
			method
		});
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'CollectStream';
	}

	/**
	 * Promise based
	 *
	 * @param {Function} thenFn
	 * @param {Function} catchFn
	 *
	 * @return {Promise<Object[]>}
	 */
	then(thenFn, catchFn) {
		if (this.promise === null) {
			let collectItems = [];
			let collectProfiles = [];
			let collectGroups = [];

			this.promise = new Promise((resolve, reject) => {
				this
					.on('error', reject)
					.on('end', () => resolve({
						items: collectItems,
						profiles: collectProfiles,
						groups: collectGroups
					}))
					.on('data', ({ items, profiles, groups }) => {
						collectItems = [...collectItems, ...items];
						collectProfiles = [...collectProfiles, ...profiles];
						collectGroups = [...collectGroups, ...groups];
					});
			});
		}

		return Promise.resolve(this.promise).then(thenFn, catchFn);
	}

	/**
	 * Fetch data
	 *
	 * @return {Promise}
	 */
	// eslint-disable-next-line no-underscore-dangle
	async _read() {
		const isNotFirst = this.total !== null && this.received !== 0;

		if (isNotFirst && (this.total - this.skipOffset) <= this.received) {
			this.push(null);

			return;
		}

		let items;
		let profiles;
		let groups;

		if (!this.supportExecute || this.parallelCount === 1) {
			const request = new Request(this.method, {
				...this.params,

				offset: this.offset
			});

			let result;
			try {
				result = await this.vk.api.callWithRequest(request);
			} catch (error) {
				const { collectAttempts } = this.vk.options;

				if (this.attempts >= collectAttempts) {
					this.emit('error', error);

					return;
				}

				this.attempts += 1;

				// eslint-disable-next-line no-underscore-dangle
				this._read();

				return;
			}

			const {
				count,
				items: collectItems,
				profiles: collectProfiles,
				groups: collectGroups
			} = result;

			if (this.total === null || this.total > count) {
				this.total = count;
			}

			[items, profiles, groups] = [collectItems, collectProfiles, collectGroups];
		} else {
			let result;
			try {
				result = await this.vk.api.execute({
					code: this.code,
					total: this.total,
					offset: this.offset,
					received: this.received
				});
			} catch (error) {
				if (error.code === APP_TOKEN_NOT_VALID) {
					this.supportExecute = false;

					debug$7('execute not supported in token');

					// eslint-disable-next-line no-underscore-dangle
					this._read();

					return;
				}

				if (error.code === RESPONSE_SIZE_TOO_BIG) {
					this.parallelCount -= 1;

					this.code = getExecuteCode({
						parallelCount: this.parallelCount,
						params: this.params,
						method: this.method
					});

					// eslint-disable-next-line no-underscore-dangle
					this._read();

					return;
				}

				const { collectAttempts } = this.vk.options;

				if (this.attempts >= collectAttempts) {
					this.emit('error', error);

					return;
				}

				this.attempts += 1;

				// eslint-disable-next-line no-underscore-dangle
				this._read();

				return;
			}

			const { response, errors } = result;

			if (errors.length > 0) {
				this.emit('error', new CollectError({
					message: 'Execute error',
					code: EXECUTE_ERROR,
					errors
				}));

				return;
			}

			const {
				total,
				items: collectItems,
				profiles: collectProfiles,
				groups: collectGroups
			} = response;

			this.total = total;

			[items, profiles, groups] = [collectItems, collectProfiles, collectGroups];
		}

		const { length } = items;

		if (length === 0) {
			this.push(null);

			return;
		}

		this.offset += length;
		this.received += length;

		const { total, received } = this;

		let percent = Math.round((received / total) * 100);

		if (Number.isNaN(percent)) {
			percent = 100;
		}

		this.push({
			received,
			percent,
			total,
			items,
			profiles,
			groups
		});
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$6.custom](depth, options) {
		const { name } = this.constructor;
		const { total, offset, received } = this;

		const payload = {
			total,
			offset,
			received
		};

		return `${options.stylize(name, 'special')} ${inspect$6(payload, options)}`;
	}
}

/**
 * List limits VK
 * Last updated 09.10.2017
 *
 * @type {Array}
 */
var LIMITS_METHODS = [
	/**
	 * Account
	 */
	['account.getActiveOffers', 100],
	['account.getBanned', 200],

	/**
	 * Ads
	 */
	['ads.getAds', 100, 2000],
	['ads.getAdsLayout', 100, 2000],
	['ads.getAdsTargeting', 100, 2000],

	/**
	 * Apps
	 */
	['apps.getCatalog', 100],
	['apps.getFriendsList', 5000],

	/**
	 * Audio
	 */
	['audio.get', 6000],
	['audio.search', 300, 1000],
	['audio.getAlbums', 100],
	['audio.getRecommendations', 1000],
	['audio.getPopular', 1000],

	/**
	 * Board
	 */
	['board.getComments', 100],
	['board.getTopics', 100],

	/**
	 * Database
	 */
	['database.getChairs', 10000],
	['database.getCities', 1000],
	['database.getCountries', 1000],
	['database.getFaculties', 10000],
	['database.getRegions', 1000],
	['database.getSchools', 10000],
	['database.getUniversities', 10000],

	/**
	 * Docs
	 */
	['docs.get', 2000, 2000],
	['docs.search', 1000, 1000],

	/**
	 * Fave
	 */
	['fave.getPosts', 100],
	['fave.getLinks', 100],
	['fave.getMarketItems', 100],
	['fave.getPhotos', 100],
	['fave.getUsers', 100],
	['fave.getVideos', 100],

	/**
	 * Friends
	 */
	['friends.get', 1000],
	['friends.getMutual', 1000],
	['friends.getMutual', 1000],
	['friends.getOnline', 1000],
	['friends.getRecent', 1000],
	['friends.getRequests', 1000],
	['friends.getSuggestions', 500],
	['friends.search', 1000],

	/**
	 * Gifts
	 */
	['gifts.get', 100],

	/**
	 * Groups
	 */
	['groups.get', 1000],
	['groups.getBanned', 200],
	['groups.getInvitedUsers', 100],
	['groups.getInvites', 100],
	['groups.getMembers', 1000],
	['groups.getRequests', 200],

	/**
	 * Leads
	 */
	['leads.getUsers', 1000],

	/**
	 * Likes
	 */
	['likes.getList', 100],

	/**
	 * Market
	 */
	['market.get', 200],
	['market.getAlbums', 100],
	['market.getCategories', 1000],
	['market.getComments', 100],
	['market.search', 200],

	/**
	 * messages
	 */
	['messages.get', 200],
	['messages.getHistory', 200],
	['messages.search', 100],
	['messages.getConversations', 200],

	/**
	 * Notes
	 */
	['notes.get', 100],
	['notes.getComments', 100],

	/**
	 * Orders
	 */
	['orders.get', 1000],

	/**
	 * Photos
	 */
	['photos.get', 1000],
	['photos.getAlbums', 100],
	['photos.getAll', 200],
	['photos.getAllComments', 100],
	['photos.getComments', 100],
	['photos.getNewTags', 100],
	['photos.getUserPhotos', 1000],
	['photos.search', 1000],

	/**
	 * Places
	 */
	['places.getCheckins', 100],
	['places.search', 1000],

	/**
	 * Polls
	 */
	['polls.getVoters', 100],

	/**
	 * Storage
	 */
	['storage.getKeys', 1000],

	/**
	 * Users
	 */
	['users.getFollowers', 1000],
	['users.getSubscriptions', 200],
	['users.search', 1000, 1000],

	/**
	 * Utils
	 */
	['utils.getLastShortenedLinks', 50],

	/**
	 * Video
	 */
	['video.get', 200],
	['video.getAlbums', 100],
	['video.getComments', 100],
	['video.search', 1000, 1000],

	/**
	 * Wall
	 */
	['wall.get', 100],
	['wall.getComments', 100],
	['wall.getReposts', 1000],
	['wall.search', 100],

	/**
	 * Widgets
	 */
	['widgets.getComments', 200],
	['widgets.getPages', 200]
];

const { inspect: inspect$7 } = nodeUtil;

class Chain {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.queue = [];
		this.started = false;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'Chain';
	}

	/**
	 * Adds method to queue
	 *
	 * @param {string} method
	 * @param {Object} params
	 *
	 * @return {Promise<*>}
	 */
	append(method, params) {
		if (this.started) {
			return Promise.reject(new VKError({
				message: 'Chain already started'
			}));
		}

		const request = new Request(method, params);

		this.queue.push(request);

		return request.promise;
	}

	/**
	 * Promise based
	 *
	 * @param {Function} thenFn
	 * @param {Function} catchFn
	 *
	 * @return {Promise<Object[]>}
	 */
	then(thenFn, catchFn) {
		return Promise.resolve(this.run()).then(thenFn, catchFn);
	}

	/**
	 * Starts the chain
	 *
	 * @return {Promise}
	 */
	async run() {
		if (this.started) {
			throw new VKError({
				message: 'Chain already started'
			});
		}

		this.started = true;

		const { queue } = this;

		if (queue.length === 0) {
			return [];
		}

		let out = {
			response: [],
			errors: []
		};

		while (queue.length > 0) {
			const tasks = queue.splice(0, 25);
			const code = getChainReturn(tasks.map(String));

			try {
				const response = await this.vk.api.execute({ code });

				resolveExecuteTask(tasks, response);

				out = {
					response: [...out.response, ...response.response],
					errors: [...out.errors, ...response.errors]
				};
			} catch (error) {
				for (const task of tasks) {
					task.reject(error);
				}

				throw error;
			}
		}

		return out;
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$7.custom](depth, options) {
		const { name } = this.constructor;
		const { started, queue } = this;

		const payload = { started, queue };

		return `${options.stylize(name, 'special')} ${inspect$7(payload, options)}`;
	}
}

const { inspect: inspect$8 } = nodeUtil;

class Collect {
	/**
	 * constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		for (const [method, limit, max] of LIMITS_METHODS) {
			const [group, name] = method.split('.');

			if (!(group in this)) {
				this[group] = {};
			}

			this[group][name] = (options = {}) => (
				new CollectStream(this.vk, {
					options,
					method,
					limit,
					max
				})
			);
		}
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'Collect';
	}

	/**
	 * Returns new Chain instance
	 *
	 * @return {Chain}
	 */
	chain() {
		return new Chain(this.vk);
	}

	/**
	 * Call multiple executors
	 *
	 * @param {string} method
	 * @param {Array}  queue
	 *
	 * @return {Promise<Array>}
	 */
	async executes(method, queue) {
		queue = queue.map(params => (
			getExecuteMethod(method, params)
		));

		const promises = [];

		while (queue.length !== 0) {
			const code = getChainReturn(queue.splice(0, 25));

			promises.push(this.vk.api.execute({ code }));
		}

		let out = {
			response: [],
			errors: []
		};

		for (const { response, errors } of await Promise.all(promises)) {
			out = {
				response: [...out.response, ...response],
				errors: [...out.errors, ...errors]
			};
		}

		return out;
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$8.custom](depth, options) {
		const { name } = this.constructor;

		return `${options.stylize(name, 'special')} {}`;
	}
}

const { inspect: inspect$9 } = nodeUtil;

class Context {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.type = null;
		this.subTypes = [];

		this.state = {};
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return this.constructor.name;
	}

	/**
	 * Checks whether the context of some of these types
	 *
	 * @param {string[]} types
	 *
	 * @return {boolean}
	 */
	is(types) {
		if (!Array.isArray(types)) {
			types = [types];
		}

		return [this.type, ...this.subTypes].some(type => (
			types.includes(type)
		));
	}

	/**
	 * Returns data for JSON
	 *
	 * @return {Object}
	 */
	toJSON() {
		return {
			...this[inspectCustomData](),

			type: this.type,
			subTypes: this.subTypes,
			state: this.state
		};
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { vk, ...payload } = this;

		return payload;
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$9.custom](depth, options) {
		const { name } = this.constructor;

		const customData = {
			...this[inspectCustomData](),

			type: this.type,
			subTypes: this.subTypes,
			state: this.state
		};

		const payload = inspect$9(customData, { ...options, compact: false });

		return `${options.stylize(name, 'special')} ${payload}`;
	}
}

class VoteContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		this.type = 'vote';
		this.subTypes = ['pull_vote'];
	}

	/**
	 * Returns the identifier poll
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.poll_id;
	}

	/**
	 * Returns the identifier user
	 *
	 * @return {number}
	 */
	get userId() {
		return this.payload.user_id;
	}

	/**
	 * Returns the identifier owner
	 *
	 * @return {number}
	 */
	get ownerId() {
		return this.payload.owner_id;
	}

	/**
	 * Returns the identifier option
	 *
	 * @return {number}
	 */
	get optionId() {
		return this.payload.option_id;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'id',
			'userId',
			'ownerId',
			'optionId'
		]);
	}
}

/**
 * Returns peer id type
 *
 * @param {number} id
 *
 * @return {string}
 */
// eslint-disable-next-line import/prefer-default-export
const getPeerType = (id) => {
	if (CHAT_PEER < id) {
		return messageSources.CHAT;
	}

	if (id < 0) {
		return messageSources.GROUP;
	}

	return messageSources.USER;
};

const transformPolling = ({ 1: fromId, 2: toId }, updateType) => ({
	from_id: fromId,
	to_id: updateType === 62
		? toId + CHAT_PEER
		: fromId,

	state: 'typing'
});

class TypingContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Array}  payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { source, updateType, groupId = null }) {
		super(vk);

		this.payload = source === updatesSources.POLLING
			? transformPolling(payload, updateType)
			: payload;

		this.type = 'typing';
		this.subTypes = [
			`typing_${getPeerType(this.fromId)}`
		];

		this.$groupId = groupId;
	}

	/**
	 * Checks is typing
	 *
	 * @return {boolean}
	 */
	get isTyping() {
		return this.payload.state === 'typing';
	}

	/**
	 * Checks is record audio message
	 *
	 * @return {boolean}
	 */
	get isAudioMessage() {
		return this.payload.state === 'audiomessage';
	}

	/**
	 * Checks that the message is typed in the dm
	 *
	 * @return {boolean}
	 */
	get isUser() {
		return this.subTypes.includes('typing_user');
	}

	/**
	 * Checks that the message is typed in the chat
	 *
	 * @return {boolean}
	 */
	get isGroup() {
		return this.subTypes.includes('typing_group');
	}

	/**
	 * Checks that the message is typed in the chat
	 *
	 * @return {boolean}
	 */
	get isChat() {
		return this.chatId !== null;
	}

	/**
	 * Returns the identifier sender
	 *
	 * @return {number}
	 */
	get fromId() {
		return this.payload.from_id;
	}

	/**
	 * Returns the identifier destination
	 *
	 * @return {number}
	 */
	get toId() {
		return this.payload.to_id;
	}

	/**
	 * Returns the identifier peer
	 *
	 * @return {number}
	 */
	// DEPRECATED: Remove in release version
	get peerId() {
		showDeprecatedMessage('TypingContext, use toId instead of peerId');

		return this.toId;
	}

	/**
	 * Returns the identifier user
	 *
	 * @return {number}
	 */
	// DEPRECATED: Remove in release version
	get userId() {
		showDeprecatedMessage('TypingContext, use fromId instead of userId');

		return this.fromId;
	}

	/**
	 * Returns the identifier chat
	 *
	 * @return {?number}
	 */
	get chatId() {
		const chatId = this.toId - CHAT_PEER;

		return chatId > 0
			? chatId
			: null;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'fromId',
			'toId',
			'chatId',
			'isUser',
			'isGroup',
			'isChat',
			'isTyping',
			'isAudioMessage'
		]);
	}
}

const { inspect: inspect$a } = nodeUtil;

const kAttachments$1 = Symbol('attachments');

class MessageReply {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {Object} vk
	 */
	constructor(payload, vk) {
		this.vk = vk;

		this.payload = payload;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'MessageForward';
	}

	/**
	 * Checks if there is text
	 *
	 * @return {boolean}
	 */
	get hasText() {
		return this.text !== null;
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the identifier message
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.id;
	}

	/**
	 * Returns the conversation message id
	 *
	 * @return {?number}
	 */
	get conversationMessageId() {
		return this.payload.conversation_message_id || null;
	}

	/**
	 * Returns the destination identifier
	 *
	 * @return {number}
	 */
	get peerId() {
		return this.payload.peer_id;
	}

	/**
	 * Returns the date when this message was created
	 *
	 * @return {number}
	 */
	get createdAt() {
		return this.payload.date;
	}

	/**
	 * Returns the date when this message was updated
	 *
	 * @return {number}
	 */
	get updatedAt() {
		return this.payload.update_time;
	}

	/**
	 * Returns the message text
	 *
	 * @return {number}
	 */
	get senderId() {
		return this.payload.from_id;
	}

	/**
	 * Returns the message text
	 *
	 * @return {string}
	 */
	get text() {
		return this.payload.text || null;
	}

	/**
	 * Returns the attachments
	 *
	 * @return {Attachment[]}
	 */
	get attachments() {
		if (!this[kAttachments$1]) {
			this[kAttachments$1] = transformAttachments(this.payload.attachments, this.vk);
		}

		return this[kAttachments$1];
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns data for JSON
	 *
	 * @return {Object}
	 */
	toJSON() {
		return copyParams(this, [
			'id',
			'conversationMessageId',
			'peerId',
			'senderId',
			'createdAt',
			'updatedAt',
			'text',
			'attachments'
		]);
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$a.custom](depth, options) {
		const { name } = this.constructor;

		const payload = copyParams(this, [
			'id',
			'conversationMessageId',
			'peerId',
			'senderId',
			'createdAt',
			'updatedAt',
			'text',
			'attachments'
		]);

		return `${options.stylize(name, 'special')} ${inspect$a(payload, { ...options, compact: false })}`;
	}
}

const { inspect: inspect$b } = nodeUtil;

const kForwards = Symbol('forwards');
const kAttachments$2 = Symbol('attachments');

class MessageForward {
	/**
	 * Constructor
	 *
	 * @param {Object} payload
	 * @param {Object} vk
	 */
	constructor(payload, vk) {
		this.vk = vk;

		this.payload = payload;
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'MessageForward';
	}

	/**
	 * Checks if there is text
	 *
	 * @return {boolean}
	 */
	get hasText() {
		return this.text !== null;
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the date when this message was created
	 *
	 * @return {number}
	 */
	get createdAt() {
		return this.payload.date;
	}

	/**
	 * Returns the date when this message was updated
	 *
	 * @return {number}
	 */
	get updatedAt() {
		return this.payload.update_time;
	}

	/**
	 * Returns the message text
	 *
	 * @return {number}
	 */
	get senderId() {
		return this.payload.from_id;
	}

	/**
	 * Returns the message text
	 *
	 * @return {string}
	 */
	get text() {
		return this.payload.text || null;
	}

	/**
	 * Returns the forwards
	 *
	 * @return {MessageForward[]}
	 */
	get forwards() {
		if (!this[kForwards]) {
			this[kForwards] = this.payload.fwd_messages
				? this.payload.fwd_messages.map(forward => (
					new MessageForward(forward, this.vk)
				))
				: [];
		}

		return this[kForwards];
	}

	/**
	 * Returns the attachments
	 *
	 * @return {Attachment[]}
	 */
	get attachments() {
		if (!this[kAttachments$2]) {
			this[kAttachments$2] = transformAttachments(this.payload.attachments, this.vk);
		}

		return this[kAttachments$2];
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns data for JSON
	 *
	 * @return {Object}
	 */
	toJSON() {
		return copyParams(this, [
			'senderId',
			'createdAt',
			'updatedAt',
			'text',
			'attachments',
			'forwards'
		]);
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$b.custom](depth, options) {
		const { name } = this.constructor;

		const payload = copyParams(this, [
			'senderId',
			'createdAt',
			'updatedAt',
			'text',
			'attachments',
			'forwards'
		]);

		return `${options.stylize(name, 'special')} ${inspect$b(payload, { ...options, compact: false })}`;
	}
}

/**
 * Special attachments in one message
 *
 * @type {Object}
 */
const specialAttachments = {
	sticker: raw => ({
		type: 'sticker',
		sticker: {
			sticker_id: Number(raw.attach1),
			product_id: Number(raw.attach1_product_id)
		}
	}),
	money_transfer: raw => ({
		type: 'money_transfer',
		money_transfer: {
			data: raw.attach1,
			amount: Number(raw.attach1_amount),
			currency: Number(raw.attach1_currency)
		}
	}),
	gift: raw => ({
		type: 'gift',
		gift: {
			id: Number(raw.attach1)
		}
	})
};

/**
 * Transform message to Object
 *
 * @param {Array} update
 *
 * @return {Object}
 */
function transformMessage({
	1: id,
	2: flags,
	3: peer,
	4: date,
	5: text,
	6: extra,
	7: attachments
}) {
	const message = {
		id,
		date,
		text,
		flags,
		geo: 'geo' in attachments
			? {}
			: null,
		random_id: extra.random_id || null,
		payload: extra.payload
			? extra.payload
			: null
	};

	message.peer_id = peer;

	if ('from' in extra) {
		message.from_id = Number(extra.from);
	} else {
		message.from_id = peer;
	}

	if (peer < 0 && message.peer_id !== message.from_id) {
		message.out = Number((flags & 2) === 0);
		message.important = (flags & 1) !== 0;
	} else {
		message.out = Number((flags & 2) !== 0);
		message.important = (flags & 8) !== 0;
	}

	if ('source_act' in extra) {
		message.action = {
			type: extra.source_act,
			text: extra.source_text,
			member_id: extra.source_mid
		};
	}

	if (attachments.attach1_type in specialAttachments) {
		message.attachments = [
			specialAttachments[attachments.attach1_type](attachments)
		];
	} else {
		const messageAttachments = [];

		for (let i = 1, key = 'attach1'; key in attachments; i += 1, key = `attach${i}`) {
			const type = attachments[`${key}_type`];

			if (type === 'link') {
				const attachment = {
					type: 'link',
					link: {
						url: attachments[`${key}_url`],
						title: attachments[`${key}_title`],
						description: attachments[`${key}_desc`]
					}
				};

				const photoKey = `${key}_photo`;

				if (attachments[photoKey]) {
					const [owner, attachmentId] = attachments[photoKey].split('_');

					attachment.link.photo = {
						id: Number(attachmentId),
						owner_id: Number(owner)
					};
				}

				messageAttachments.push(attachment);

				continue;
			}

			const [owner, attachmentId] = attachments[key].split('_');

			const attachment = {
				type,
				[type]: {
					id: Number(attachmentId),
					owner_id: Number(owner)
				}
			};

			const kindKey = `${key}_kind`;

			if (type === 'doc' && kindKey in attachments) {
				attachment[type].kind = attachments[kindKey];
			}

			messageAttachments.push(attachment);
		}

		message.attachments = messageAttachments;
	}

	let { fwd = null } = attachments;

	// Now long poll receive such forward messages 0_0,0_0
	if (fwd !== null) {
		const indexColon = fwd.indexOf(':');
		if (indexColon !== -1) {
			fwd = fwd.substring(0, indexColon);
		}

		message.fwd_messages = fwd
			.split(',')
			.map((attachment) => {
				const [owner] = attachment.split('_');

				return {
					date: 0,
					from_id: Number(owner),
					text: '',
					fwd_messages: [],
					attachments: [],
					update_time: 0
				};
			});
	}

	return message;
}

const getForwards = (rootForwards) => {
	const forwards = [];

	for (const forward of rootForwards) {
		forwards.push(
			forward,
			...getForwards(forward.forwards)
		);
	}

	return forwards;
};

const kFlatten = Symbol('flatten');

class MessageForwardsCollection extends Array {
	/**
	 * Returns a flat copy of forwards
	 *
	 * @return {MessageForward[]}
	 */
	get flatten() {
		if (!this[kFlatten]) {
			this[kFlatten] = getForwards(this);
		}

		return this[kFlatten];
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type) {
		return this.flatten.some(forward => (
			forward.hasAttachments(type)
		));
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type) {
		const attachments = this.flatten.map(forward => (
			forward.getAttachments(type)
		));

		return [].concat(...attachments);
	}
}

const subTypesEnum = {
	4: 'new_message',
	5: 'edit_message',
	message_new: 'new_message',
	message_edit: 'edit_message',
	message_reply: 'reply_message'
};

const kForwards$1 = Symbol('forwards');
const kReplyMessage = Symbol('replyMessage');

const kAttachments$3 = Symbol('attachments');

class MessageContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { source, updateType, groupId = null }) {
		super(vk);

		if (source === updatesSources.POLLING) {
			payload = transformMessage(payload);

			this.$filled = false;
		} else {
			this.$filled = true;
		}

		this.$groupId = groupId;

		this.applyPayload(payload);

		const { eventType } = this;

		this.type = 'message';
		this.subTypes = [
			!eventType
				? subTypesEnum[updateType]
				: eventType
		];
	}

	/**
	 * Load message payload
	 *
	 * @return {Promise}
	 */
	async loadMessagePayload() {
		if (this.$filled) {
			return;
		}

		const { items } = this.id !== 0
			? await this.vk.api.messages.getById({
				message_ids: this.id
			})
			: await this.vk.api.messages.getByConversationMessageId({
				peer_id: this.peerId,
				conversation_message_ids: this.conversationMessageId
			});

		const [message] = items;

		this[kForwards$1] = null;
		this[kAttachments$3] = null;
		this[kReplyMessage] = null;

		this.applyPayload(message);

		this.$filled = true;
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Checks if there is text
	 *
	 * @return {boolean}
	 */
	get hasText() {
		return this.text !== null;
	}

	/**
	 * Checks for reply message
	 *
	 * @return {boolean}
	 */
	get hasReplyMessage() {
		return this.replyMessage !== null;
	}

	/**
	 * Checks for forwarded messages
	 *
	 * @return {boolean}
	 */
	get hasForwards() {
		return this.forwards.length > 0;
	}

	/**
	 * Checks for hast message payload
	 *
	 * @return {boolean}
	 */
	get hasMessagePayload() {
		return Boolean(this.payload.payload);
	}

	/**
	 * Checks if there is text
	 *
	 * @return {boolean}
	 */
	get hasGeo() {
		return Boolean(this.payload.geo);
	}

	/**
	 * Checks is a chat
	 *
	 * @return {boolean}
	 */
	get isChat() {
		return this.peerType === messageSources.CHAT;
	}

	/**
	 * Check is a user
	 *
	 * @return {boolean}
	 */
	get isUser() {
		return this.senderType === messageSources.USER;
	}

	/**
	 * Checks is a group
	 *
	 * @return {boolean}
	 */
	get isGroup() {
		return this.senderType === messageSources.GROUP;
	}

	/**
	 * Checks is from the user
	 *
	 * @return {boolean}
	 */
	get isFromUser() {
		return this.peerType === messageSources.USER;
	}

	/**
	 * Checks is from the group
	 *
	 * @return {boolean}
	 */
	get isFromGroup() {
		return this.peerType === messageSources.GROUP;
	}

	/**
	 * Check is special event
	 *
	 * @return {boolean}
	 */
	get isEvent() {
		return this.eventType !== null;
	}

	/**
	 * Checks whether the message is outbox
	 *
	 * @return {boolean}
	 */
	get isOutbox() {
		return Boolean(this.payload.out);
	}

	/**
	 * Checks whether the message is inbox
	 *
	 * @return {boolean}
	 */
	get isInbox() {
		return !this.isOutbox;
	}

	/**
	 * Checks that the message is important
	 *
	 * @return {boolean}
	 */
	get isImportant() {
		return this.payload.important;
	}

	/**
	 * Returns the identifier message
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.id;
	}

	/**
	 * Returns the conversation message id
	 *
	 * @return {?number}
	 */
	get conversationMessageId() {
		return this.payload.conversation_message_id || null;
	}

	/**
	 * Returns the destination identifier
	 *
	 * @return {number}
	 */
	get peerId() {
		return this.payload.peer_id;
	}

	/**
	 * Returns the peer type
	 *
	 * @return {string}
	 */
	get peerType() {
		return getPeerType(this.payload.peer_id);
	}

	/**
	 * Returns the sender identifier
	 *
	 * @return {number}
	 */
	get senderId() {
		return this.payload.from_id;
	}

	/**
	 * Returns the sender type
	 *
	 * @return {string}
	 */
	get senderType() {
		return getPeerType(this.payload.from_id);
	}

	/**
	 * Returns the identifier chat
	 *
	 * @return {?number}
	 */
	get chatId() {
		if (!this.isChat) {
			return null;
		}

		return this.peerId - CHAT_PEER;
	}

	/**
	 * Returns the date when this message was created
	 *
	 * @return {number}
	 */
	get createdAt() {
		return this.payload.date;
	}

	/**
	 * Returns geo
	 *
	 * @return {?Object}
	 */
	get geo() {
		if (!this.hasGeo) {
			return null;
		}

		if (!this.$filled) {
			throw new VKError({
				message: 'The message payload is not fully loaded'
			});
		}

		return this.payload.geo;
	}

	/**
	 * Returns the event name
	 *
	 * @return {?string}
	 */
	get eventType() {
		return (
			this.payload.action
			&& this.payload.action.type
		) || null;
	}

	/**
	 * Returns the event member id
	 *
	 * @return {?number}
	 */
	get eventMemberId() {
		return (
			this.payload.action
			&& this.payload.action.member_id
		) || null;
	}

	/**
	 * Returns the event name
	 *
	 * @return {?string}
	 */
	get eventText() {
		return (
			this.payload.action
			&& this.payload.action.text
		) || null;
	}

	/**
	 * Returns the event email
	 *
	 * @return {?string}
	 */
	get eventEmail() {
		return (
			this.payload.action
			&& this.payload.action.email
		) || null;
	}

	/**
	 * Returns the message payload
	 *
	 * @return {?*}
	 */
	get messagePayload() {
		const { payload = null } = this.payload;

		if (payload === null) {
			return null;
		}

		return JSON.parse(payload);
	}

	/**
	 * Returns the forwards
	 */
	get forwards() {
		if (!this[kForwards$1]) {
			this[kForwards$1] = this.payload.fwd_messages
				? new MessageForwardsCollection(...this.payload.fwd_messages.map(forward => (
					new MessageForward(forward, this.vk)
				)))
				: new MessageForwardsCollection();
		}

		return this[kForwards$1];
	}

	/**
	 * Returns the reply message
	 */
	get replyMessage() {
		if (!this[kReplyMessage]) {
			this[kReplyMessage] = this.payload.reply_message
				? new MessageReply(this.payload.reply_message, this.vk)
				: null;
		}

		return this[kReplyMessage];
	}

	/**
	 * Returns the attachments
	 */
	get attachments() {
		if (!this[kAttachments$3]) {
			this[kAttachments$3] = transformAttachments(this.payload.attachments, this.vk);
		}

		return this[kAttachments$3];
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Gets a link to invite the user to a conversation
	 *
	 * @param {Object} params
	 *
	 * @type {Promise<Object>}
	 */
	getInviteLink(params = {}) {
		return this.vk.api.messages.getInviteLink({
			...params,

			peer_id: this.peerId
		});
	}

	/**
	 * Edits a message
	 *
	 * @param {Object} params
	 *
	 * @return {Promise}
	 */
	editMessage(params) {
		return this.vk.api.messages.edit({
			attachment: this.attachments.filter(attachment => (
				attachment.canBeAttached
			)),
			message: this.text,
			keep_forward_messages: 1,
			keep_snippets: 1,

			...params,

			peer_id: this.peerId,
			message_id: this.id
		});
	}

	/**
	 * Edits a message text
	 *
	 * @param {string} message
	 *
	 * @return {Promise}
	 */
	async editMessageText(message) {
		const response = await this.editMessage({ message });

		this.text = message;

		return response;
	}

	/**
	 * Sends a message to the current dialog
	 *
	 * @param {string|Object} text
	 * @param {Object}        params
	 *
	 * @return {Promise}
	 */
	send(text, params) {
		return this.vk.api.messages.send({
			peer_id: this.peerId,

			...(
				typeof text !== 'object'
					? {
						message: text,

						...params
					}
					: text
			)
		});
	}

	/**
	 * Responds to the current message
	 *
	 * @param {string|Object} text
	 * @param {Object}        params
	 *
	 * @return {Promise}
	 */
	reply(text, params) {
		return this.send({
			reply_to: this.id,

			...(
				typeof text !== 'object'
					? {
						message: text,

						...params
					}
					: text
			)
		});
	}

	/**
	 * Sends a sticker to the current dialog
	 *
	 * @param {number} id
	 *
	 * @return {Promise}
	 */
	sendSticker(id) {
		return this.send({
			sticker_id: id
		});
	}

	/**
	 * Sends a photo to the current dialog
	 *
	 * @param {*[]} sources
	 * @param {Object}  params
	 *
	 * @return {Promise}
	 */
	async sendPhoto(sources, params = {}) {
		if (!Array.isArray(sources)) {
			sources = [sources];
		}

		const attachment = await Promise.all(sources.map(source => (
			this.vk.upload.messagePhoto({
				source
			})
		)));

		const response = await this.send({
			...params,

			attachment
		});

		return response;
	}

	/**
	 * Sends a document to the current dialog
	 *
	 * @param {*[]} sources
	 * @param {Object}  params
	 *
	 * @return {Promise}
	 */
	async sendDocument(sources, params = {}) {
		if (!Array.isArray(sources)) {
			sources = [sources];
		}

		const attachment = await Promise.all(sources.map(source => (
			this.vk.upload.messageDocument({
				peer_id: this.senderId,

				source
			})
		)));

		const response = await this.send({
			...params,

			attachment
		});

		return response;
	}

	/**
	 * Sends a audio message to the current dialog
	 *
	 * @param {*}  sourxe
	 * @param {Object} params
	 *
	 * @return {Promise}
	 */
	async sendAudioMessage(source, params = {}) {
		const attachment = await this.vk.upload.audioMessage({
			peer_id: this.senderId,

			source
		});

		const response = await this.send({
			...params,

			attachment
		});

		return response;
	}

	/**
	 * Changes the status of typing in the dialog
	 *
	 * @return {Promise<boolean>}
	 */
	async setActivity() {
		const isActivited = await this.vk.api.messages.setActivity({
			peer_id: this.peerId,
			type: 'typing'
		});

		return Boolean(isActivited);
	}

	/**
	 * Marks messages as important or removes a mark.
	 *
	 * @param {Array}  ids
	 * @param {Object} options
	 *
	 * @return {Promise<Array>}
	 */
	async markAsImportant(
		ids = [this.id],
		options = { important: Number(!this.isImportant) }
	) {
		const messageIds = await this.vk.api.messages.markAsImportant({
			...options,

			message_ids: ids.join(',')
		});

		if (messageIds.includes(this.id)) {
			this.payload.important = Boolean(options.important);
		}

		return messageIds;
	}

	/**
	 * Deletes the message
	 *
	 * @param {Array}  ids
	 * @param {Object} options
	 *
	 * @return {Promise<number[]>}
	 */
	async deleteMessage(ids = [this.id], options = { spam: 0 }) {
		const messageIds = await this.vk.api.messages.delete({
			...options,

			message_ids: ids.join(',')
		});

		return messageIds;
	}

	/**
	 * Restores the message
	 *
	 * @return {Promise<boolean>}
	 */
	async restoreMessage() {
		const isRestored = await this.vk.api.messages.restore({
			message_id: this.id
		});

		return Boolean(isRestored);
	}

	/**
	 * Checks that in a chat
	 */
	assertIsChat() {
		if (!this.isChat) {
			throw new VKError({
				message: 'This method is only available in chat'
			});
		}
	}

	/**
	 * Rename the chat
	 *
	 * @param {string} title
	 *
	 * @return {Promise<boolean>}
	 */
	async renameChat(title) {
		this.assertIsChat();

		const isRenamed = await this.vk.api.messages.editChat({
			chat_id: this.chatId,
			title
		});

		return Boolean(isRenamed);
	}

	/**
	 * Sets a new image for the chat
	 *
	 * @param {*}  source
	 * @param {Object} params
	 *
	 * @return {Promise<Object>}
	 */
	async newChatPhoto(source, params = {}) {
		this.assertIsChat();

		const response = await this.vk.upload.chatPhoto({
			...params,

			chat_id: this.chatId,
			source
		});

		return response;
	}

	/**
	 * Remove the chat photo
	 *
	 * @return {Promise<boolean>}
	 */
	async deleteChatPhoto() {
		this.assertIsChat();

		return this.vk.api.messages.deleteChatPhoto({
			chat_id: this.chatId
		});
	}

	/**
	 * Invites a new user
	 *
	 * @param {number} id
	 *
	 * @return {Promise<boolean>}
	 */
	async inviteUser(id = this.eventMemberId) {
		this.assertIsChat();

		const isInvited = await this.vk.api.messages.removeChatUser({
			chat_id: this.chatId,
			user_id: id
		});

		return Boolean(isInvited);
	}

	/**
	 * Excludes user
	 *
	 * @param {number} id
	 *
	 * @return {Promise<boolean>}
	 */
	async kickUser(id = this.eventMemberId) {
		this.assertIsChat();

		const isKicked = await this.vk.api.messages.removeChatUser({
			chat_id: this.chatId,
			member_id: id
		});

		return Boolean(isKicked);
	}

	/**
	 * Pins a message
	 *
	 * @return {Promise<boolean>}
	 */
	async pinMessage() {
		this.assertIsChat();

		const isPinned = await this.vk.api.messages.pin({
			peer_id: this.peerId,
			message_id: this.id
		});

		return Boolean(isPinned);
	}

	/**
	 * Unpins a message
	 *
	 * @return {Promise<boolean>}
	 */
	async unpinMessage() {
		this.assertIsChat();

		const isUnpinned = await this.vk.api.messages.unpin({
			peer_id: this.peerId,
			message_id: this.id
		});

		return Boolean(isUnpinned);
	}

	/**
	 * Applies the payload
	 *
	 * @param {Object} payload
	 */
	applyPayload(payload) {
		this.payload = payload;

		this.text = payload.text
			? unescapeHTML(payload.text)
			: null;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		const beforeAttachments = [];

		if (this.isEvent) {
			beforeAttachments.push(
				'eventType',
				'eventMemberId',
				'eventText',
				'eventEmail'
			);
		}

		if (this.hasReplyMessage) {
			beforeAttachments.push('replyMessage');
		}

		const afterAttachments = [];

		if (this.hasMessagePayload) {
			afterAttachments.push('messagePayload');
		}

		afterAttachments.push('isOutbox');

		if (this.$match) {
			afterAttachments.push('$match');
		}

		return copyParams(this, [
			'id',
			'conversationMessageId',
			'peerId',
			'peerType',
			'senderId',
			'senderType',
			'createdAt',
			'text',
			...beforeAttachments,
			'forwards',
			'attachments',
			...afterAttachments
		]);
	}
}

const subTypes = {
	wall_post_new: 'new_wall_post',
	wall_repost: 'new_wall_repost'
};

class WallPostContext extends Context {
	/**
	 * constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { updateType, groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		this.wall = new WallAttachment(payload, vk);

		this.type = 'wall_post';
		this.subTypes = [
			subTypes[updateType]
		];
	}

	/**
	 * Checks is repost
	 *
	 * @return {boolean}
	 */
	get isRepost() {
		return this.subTypes.includes('new_wall_repost');
	}

	/**
	 * Removes a record from the wall
	 *
	 * @return {Promise}
	 */
	deletePost() {
		const { wall } = this;

		return this.vk.api.wall.delete({
			post_id: wall.id,
			owner_id: wall.ownerId
		});
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'wall',
			'isRepost'
		]);
	}
}

class StreamingContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload) {
		super(vk);

		this.payload = payload;

		const { action, event_type: type } = payload;

		this.attachments = transformAttachments(payload.attachments, vk);

		this.type = 'publication';
		this.subTypes = [
			`publication_${type}`,
			`${action}_publication`,
			`${action}_publication_${type}`
		];
	}

	/**
	 * Checks is new object
	 *
	 * @return {boolean}
	 */
	get isNew() {
		return this.actionType === 'new';
	}

	/**
	 * Checks is update object
	 *
	 * @return {boolean}
	 */
	get isUpdate() {
		return this.actionType === 'update';
	}

	/**
	 * Checks is delete object
	 *
	 * @return {boolean}
	 */
	get isDelete() {
		return this.actionType === 'delete';
	}

	/**
	 * Checks is restore object
	 *
	 * @return {boolean}
	 */
	get isRestore() {
		return this.actionType === 'restore';
	}

	/**
	 * Checks is post event
	 *
	 * @return {boolean}
	 */
	get isPost() {
		return this.eventType === 'post';
	}

	/**
	 * Checks is share event
	 *
	 * @return {boolean}
	 */
	get isShare() {
		return this.eventType === 'share';
	}

	/**
	 * Checks is comment event
	 *
	 * @return {boolean}
	 */
	get isComment() {
		return this.eventType === 'comment';
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the event URL
	 *
	 * @return {string}
	 */
	get url() {
		return this.payload.event_url;
	}

	/**
	 * Returns the creation time
	 *
	 * @return {number}
	 */
	get createdAt() {
		return this.payload.creation_time;
	}

	/**
	 * Returns the text of the post
	 *
	 * @return {?string}
	 */
	get text() {
		return this.payload.text || null;
	}

	/**
	 * Returns the text of the shared post
	 *
	 * @return {?string}
	 */
	get sharedText() {
		return this.payload.shared_post_text || null;
	}

	/**
	 * Returns the creation time from original post
	 *
	 * @return {?number}
	 */
	get sharedAt() {
		return this.payload.shared_post_creation_time || null;
	}

	/**
	 * Returns the action type
	 *
	 * @return {string}
	 */
	get actionType() {
		return this.payload.action;
	}

	/**
	 * Returns the event type
	 *
	 * @return {string}
	 */
	get eventType() {
		return this.payload.event_type;
	}

	/**
	 * Returns the creation time from
	 *
	 * @return {number}
	 */
	get actionAt() {
		return this.payload.action_time;
	}

	/**
	 * Returns the geo location
	 *
	 * @return {Object}
	 */
	get geo() {
		return this.payload.geo;
	}

	/**
	 * Returns the rule tags
	 *
	 * @return {string[]}
	 */
	get tags() {
		return this.payload.tags;
	}

	/**
	 * Returns the identifier signer user
	 *
	 * @return {number}
	 */
	get signerId() {
		return this.payload.signer_id;
	}

	/**
	 * Returns the information of author
	 *
	 * @return {Object}
	 */
	get author() {
		return this.payload.author;
	}

	/**
	 * Returns the identifier author
	 *
	 * @return {number}
	 */
	get authorId() {
		return this.payload.author.id;
	}

	/**
	 * Returns the author url
	 *
	 * @return {string}
	 */
	get authorUrl() {
		return this.payload.author.author_url;
	}

	/**
	 * Returns the identifier of the author of the original post
	 *
	 * @return {?number}
	 */
	get sharedAuthorId() {
		return this.payload.author.shared_post_author_id || null;
	}

	/**
	 * Returns the author url of the original post
	 *
	 * @return {?string}
	 */
	get sharedAuthorUrl() {
		return this.payload.author.shared_post_author_url || null;
	}

	/**
	 * Returns the author platform
	 *
	 * @return {?string}
	 */
	get authorPlatform() {
		return platforms.get(this.payload.author.platform);
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		const properties = [
			'url',
			'created',
			'text',
			'sharedText',
			'sharedAt',
			'actionType',
			'eventType',
			'actionAt',
			'geo',
			'tags',
			'signerId',
			'author',
			'authorId',
			'authorUrl',
			'sharedAuthorId',
			'sharedAuthorUrl',
			'authorPlatform',
			'isNew',
			'isUpdate',
			'isDelete',
			'isRestore',
			'isPost',
			'isShare',
			'isComment'
		];

		const filtredEmptyProperties = properties.filter(property => (
			this[property] !== null
		));

		return copyParams(this, filtredEmptyProperties);
	}
}

/**
 * Causes of blocking
 *
 * @type {Map}
 */
const reasonNames = new Map([
	[0, 'other'],
	[1, 'spam'],
	[2, 'members_insult'],
	[3, 'obscene_expressions'],
	[4, 'messages_off_topic']
]);

const subTypes$1 = {
	user_block: 'block_group_user',
	user_unblock: 'unblock_group_user'
};

class GroupUserContext extends Context {
	/**
	 * Constructror
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { updateType, groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		this.type = 'group_user';
		this.subTypes = [
			subTypes$1[updateType]
		];
	}

	/**
	 * Checks is join user
	 *
	 * @return {boolean}
	 */
	get isBlocked() {
		return this.subTypes.includes('block_group_user');
	}

	/**
	 * Checks is leave user
	 *
	 * @return {boolean}
	 */
	get isUnblocked() {
		return this.subTypes.includes('unblock_group_user');
	}

	/**
	 * Checks that the block has expired
	 *
	 * @return {?boolean}
	 */
	get isExpired() {
		if (this.isBlocked) {
			return null;
		}

		return Boolean(this.payload.by_end_date);
	}

	/**
	 * Returns the identifier admin
	 *
	 * @return {?number}
	 */
	get adminId() {
		return this.payload.admin_id;
	}

	/**
	 * Returns the identifier user
	 *
	 * @return {number}
	 */
	get userId() {
		return this.payload.user_id;
	}

	/**
	 * Returns the reason for the ban
	 *
	 * @return {?number}
	 */
	get reasonId() {
		return this.payload.reason || null;
	}

	/**
	 * Returns the reason name for the ban
	 *
	 * @return {?string}
	 */
	get reasonName() {
		return reasonNames.get(this.reasonId);
	}

	/**
	 * Returns the unblock date or null if permanent
	 *
	 * @return {?Date}
	 */
	get unblockAt() {
		return this.payload.unblock_date
			? new Date(this.payload.unblock_date)
			: null;
	}

	/**
	 * Returns the administrator comment to block
	 *
	 * @return {?string}
	 */
	get comment() {
		return this.payload.comment || null;
	}

	/**
	 * Adds a user to the community blacklist
	 *
	 * @param {Object} params
	 *
	 * @return {Promise}
	 */
	ban(params) {
		if (this.isBlocked) {
			return Promise.reject(new VKError({
				message: 'User is blocked'
			}));
		}

		return this.vk.api.groups.ban({
			...params,

			group_id: this.$groupId,
			user_id: this.userId
		});
	}

	/**
	 * Adds a user to the community blacklist
	 *
	 * @return {Promise}
	 */
	unban() {
		if (this.isUnblocked) {
			return Promise.reject(new VKError({
				message: 'User is not blocked'
			}));
		}

		return this.vk.api.groups.unban({
			group_id: this.$groupId,
			user_id: this.userId
		});
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'adminId',
			'userId',
			'reasonId',
			'reasonName',
			'comment',
			'isExpired',
			'isBlocked',
			'isUnblocked'
		]);
	}
}

const subTypes$2 = {
	8: 'user_online',
	9: 'user_offline'
};

class UserOnlineContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Array}  payload
	 * @param {Object} options
	 */
	constructor(vk, [eventId, userId, extra, date]) {
		super(vk);

		this.payload = {
			user_id: -userId,
			extra,
			date
		};

		this.type = 'user_active';
		this.subTypes = [
			subTypes$2[eventId]
		];
	}

	/**
	 * Checks that the user is online
	 *
	 * @return {boolean}
	 */
	get isUserOnline() {
		return this.subTypes.includes('user_online');
	}

	/**
	 * Checks that the user is online
	 *
	 * @return {boolean}
	 */
	get isUserOffline() {
		return this.subTypes.includes('user_offline');
	}

	/**
	 * Checks that the user has logged out of the network himself
	 *
	 * @return {boolean}
	 */
	get isSelfExit() {
		return this.isUserOffline && !this.payload.extra;
	}

	/**
	 * Checks that the user logged out a timeout
	 *
	 * @return {boolean}
	 */
	get isTimeoutExit() {
		return this.isUserOffline && Boolean(this.payload.extra);
	}

	/**
	 * Returns the user id
	 *
	 * @return {?number}
	 */
	get userId() {
		return this.payload.user_id || null;
	}

	/**
	 * Returns the date when this event was created
	 *
	 * @return {number}
	 */
	get createdAt() {
		return this.payload.date;
	}

	/**
	 * Returns the name of the platform from which the user entered
	 *
	 * @return {?string}
	 */
	get platformName() {
		return platforms.get(this.payload.extra);
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'userId',
			'createdAt',
			'platformName',
			'isSelfExit',
			'isTimeoutExit',
			'isUserOnline',
			'isUserOffline'
		]);
	}
}

const subTypes$3 = {
	10: 'remove_dialog_flags',
	11: 'update_dialog_flags',
	12: 'set_dialog_flags'
};

class DialogFlagsContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Array}  payload
	 * @param {Object} options
	 */
	constructor(vk, [eventId, peerId, flags]) {
		super(vk);

		this.payload = {
			peer_id: peerId,
			flags
		};

		this.type = 'dialog_flags';
		this.subTypes = [
			subTypes$3[eventId]
		];
	}

	/**
	 * Checks that an important dialogue
	 *
	 * @return {boolean}
	 */
	get isImportant() {
		return Boolean(this.flags & 1);
	}

	/**
	 * Checks that the unanswered dialog
	 *
	 * @return {boolean}
	 */
	get isUnanswered() {
		return Boolean(this.flags & 2);
	}

	/**
	 * Returns the destination identifier
	 *
	 * @return {number}
	 */
	get peerId() {
		return this.payload.peer_id;
	}

	/**
	 * Returns the values of the flags
	 *
	 * @return {number}
	 */
	get flags() {
		return this.payload.flags;
	}

	/**
	 * Marks the conversation as answered or unchecked.
	 *
	 * @param {Object} params
	 *
	 * @return {Promise}
	 */
	markAsAnsweredConversation(params) {
		return this.vk.api.messages.markAsAnsweredConversation({
			...params,

			peer_id: this.peerId
		});
	}

	/**
	 * Marks the conversation as important or removes the mark
	 *
	 * @param {Object} params
	 *
	 * @return {Promise}
	 */
	markAsImportantConversation(params) {
		return this.vk.api.messages.markAsImportantConversation({
			...params,

			peer_id: this.peerId
		});
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'peerId',
			'flags',
			'isImportant',
			'isUnanswered'
		]);
	}
}

const subTypes$4 = {
	group_change_photo: 'group_update_photo',
	group_update_officers: 'group_update_officers',
	group_change_settings: 'group_update_settings'
};

class GroupUpdateContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { updateType, groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		this.attachments = updateType === 'group_change_photo'
			? [new PhotoAttachment(payload.photo, vk)]
			: [];

		this.type = 'group_update';
		this.subTypes = [
			subTypes$4[updateType]
		];
	}

	/**
	 * Checks is change photo
	 *
	 * @return {boolean}
	 */
	get isChangePhoto() {
		return this.subTypes.includes('group_update_photo');
	}

	/**
	 * Checks is change officers
	 *
	 * @return {boolean}
	 */
	get isChangeOfficers() {
		return this.subTypes.includes('group_update_officers');
	}

	/**
	 * Checks is change settings
	 *
	 * @return {boolean}
	 */
	get isChangeSettings() {
		return this.subTypes.includes('group_update_settings');
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the identifier admin
	 *
	 * @return {?number}
	 */
	get adminId() {
		return this.payload.admin_id || null;
	}

	/**
	 * Returns the identifier user
	 *
	 * @return {number}
	 */
	get userId() {
		return this.payload.user_id;
	}

	/**
	 * Returns the old level permission
	 *
	 * @return {?number}
	 */
	get oldLevel() {
		return this.payload.level_old || null;
	}

	/**
	 * Returns the new level permission
	 *
	 * @return {?number}
	 */
	get newLevel() {
		return this.payload.level_new || null;
	}

	/**
	 * Returns the changes settings
	 *
	 * @return {?Object}
	 */
	get changes() {
		return this.payload.changes || null;
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'adminId',
			'userId',
			'oldLevel',
			'newLevel',
			'changes',
			'attachments'
		]);
	}
}

const subTypes$5 = {
	group_leave: 'leave_group_member',
	group_join: 'join_group_member'
};

class GroupMemberContext extends Context {
	/**
	 * Constructro
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { updateType, groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		this.type = 'group_member';
		this.subTypes = [
			subTypes$5[updateType]
		];
	}

	/**
	 * Checks is join user
	 *
	 * @return {boolean}
	 */
	get isJoin() {
		return this.subTypes.includes('join_group_member');
	}

	/**
	 * Checks is leave user
	 *
	 * @return {boolean}
	 */
	get isLeave() {
		return this.subTypes.includes('leave_group_member');
	}

	/**
	 * Checks is self leave user
	 *
	 * @return {?boolean}
	 */
	get isSelfLeave() {
		if (this.isJoin) {
			return null;
		}

		return Boolean(this.payload.self);
	}

	/**
	 * Returns the identifier user
	 *
	 * @return {number}
	 */
	get userId() {
		return this.payload.user_id;
	}

	/**
	 * Returns the join type
	 *
	 * @return {?string}
	 */
	get joinType() {
		if (this.isLeave) {
			return null;
		}

		return this.payload.join_type;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'userId',
			'joinType',
			'isJoin',
			'isLeave',
			'isSelfLeave'
		]);
	}
}

const subTypes$6 = {
	message_allow: 'message_subscribe',
	message_deny: 'message_unsubscribe'
};

class MessageAllowContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { updateType, groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		this.type = 'message_subscribers';
		this.subTypes = [
			subTypes$6[updateType]
		];
	}

	/**
	 * Checks that the user has subscribed to messages
	 *
	 * @return {boolean}
	 */
	get isSubscribed() {
		return this.subTypes.includes('message_subscribe');
	}

	/**
	 * Checks that the user has unsubscribed from the messages
	 *
	 * @return {boolean}
	 */
	get isUbsubscribed() {
		return this.subTypes.includes('message_unsubscribe');
	}

	/**
	 * Returns the identifier user
	 *
	 * @return {number}
	 */
	get userId() {
		return this.payload.user_id;
	}

	/**
	 * Returns the key
	 *
	 * @return {?string}
	 */
	get key() {
		return this.payload.key || null;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'userId',
			'key',
			'isSubscribed',
			'isUbsubscribed'
		]);
	}
}

const subTypes$7 = {
	6: 'read_inbox_messages',
	7: 'read_outbox_messages'
};

class ReadMessagesContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Array}  payload
	 * @param {Object} options
	 */
	constructor(vk, [eventId, peerId, id]) {
		super(vk);

		this.payload = {
			peer_id: peerId,
			id
		};

		this.type = 'read_messages';
		this.subTypes = [
			subTypes$7[eventId]
		];
	}

	/**
	 * Checks that inbox messages are read
	 *
	 * @return {boolean}
	 */
	get isInbox() {
		return this.subTypes.includes('read_inbox_messages');
	}

	/**
	 * Checks that outbox messages are read
	 *
	 * @return {boolean}
	 */
	get isOutbox() {
		return this.subTypes.includes('read_outbox_messages');
	}

	/**
	 * Returns the ID before the message read
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.id;
	}

	/**
	 * Returns the peer ID
	 *
	 * @return {number}
	 */
	get peerId() {
		return this.payload.peer_id;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'id',
			'peerId',
			'isInbox',
			'isOutbox'
		]);
	}
}

const subTypes$8 = {
	1: 'update_message_flags',
	2: 'set_message_flags',
	3: 'remove_message_flags'
};

class MessageFlagsContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Array}  payload
	 * @param {Object} options
	 */
	constructor(vk, [eventId, id, flags, peerId]) {
		super(vk);

		this.payload = {
			peer_id: peerId,
			flags,
			id
		};

		this.type = 'message_flags';
		this.subTypes = [
			subTypes$8[eventId]
		];
	}

	/**
	 * Verifies that the message is not read
	 *
	 * @return {boolean}
	 */
	get isUnread() {
		return Boolean(this.flags & 1);
	}

	/**
	 * Checks that the outgoing message
	 *
	 * @return {boolean}
	 */
	get isOutbox() {
		return Boolean(this.flags & 2);
	}

	/**
	 * Verifies that a reply has been created to the message
	 *
	 * @return {boolean}
	 */
	get isReplied() {
		return Boolean(this.flags & 4);
	}

	/**
	 * Verifies that the marked message
	 *
	 * @return {boolean}
	 */
	get isImportant() {
		return Boolean(this.flags & 8);
	}

	/**
	 * Verifies that the message was sent via chat
	 *
	 * @return {boolean}
	 */
	get isChat() {
		return Boolean(this.flags & 16);
	}

	/**
	 * Verifies that the message was sent by a friend
	 *
	 * @return {boolean}
	 */
	get isFriends() {
		return Boolean(this.flags & 32);
	}

	/**
	 * Verifies that the message is marked as "Spam"
	 *
	 * @return {boolean}
	 */
	get isSpam() {
		return Boolean(this.flags & 64);
	}

	/**
	 * Verifies that the message has been deleted (in the Recycle Bin)
	 *
	 * @return {boolean}
	 */
	get isDeleted() {
		return Boolean(this.flags & 128);
	}

	/**
	 * Verifies that the message was verified by the user for spam
	 *
	 * @return {boolean}
	 */
	get isFixed() {
		return Boolean(this.flags & 256);
	}

	/**
	 * Verifies that the message contains media content
	 *
	 * @return {boolean}
	 */
	get isMedia() {
		return Boolean(this.flags & 512);
	}

	/**
	 * Checks that a welcome message from the community
	 *
	 * @return {boolean}
	 */
	get isHidden() {
		return Boolean(this.flags & 65536);
	}

	/**
	 * Message deleted for all recipients
	 *
	 * @return {boolean}
	 */
	get isDeletedForAll() {
		return Boolean(this.flags & 131072);
	}

	/**
	 * Returns the message ID
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.id;
	}

	/**
	 * Returns the destination identifier
	 *
	 * @return {number}
	 */
	get peerId() {
		return this.payload.peer_id;
	}

	/**
	 * Returns the values of the flags
	 *
	 * @return {number}
	 */
	get flags() {
		return this.payload.flags;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'id',
			'peerId',
			'flags'
		]);
	}
}

/**
 * Find types
 *
 * ```
 * wall_reply_new
 * ```
 *
 * @type {RegExp}
 */
const findTypes = /([^_]+)_([^_]+)_([^_]+)/;

class CommentActionContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { updateType, groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		this.attachments = transformAttachments(payload.attachments, vk);

		const { 1: initiator, 3: action } = updateType.match(findTypes);

		this.type = 'comment';
		this.subTypes = [
			`${initiator}_comment`,
			`${action}_${initiator}_comment`
		];
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Checks is new comment
	 *
	 * @return {boolean}
	 */
	get isNew() {
		return this.includesFromSubType('new');
	}

	/**
	 * Checks is edit comment
	 *
	 * @return {boolean}
	 */
	get isEdit() {
		return this.includesFromSubType('edit');
	}

	/**
	 * Checks is delete comment
	 *
	 * @return {boolean}
	 */
	get isDelete() {
		return this.includesFromSubType('delete');
	}

	/**
	 * Checks is restore comment
	 *
	 * @return {boolean}
	 */
	get isRestore() {
		return this.includesFromSubType('restore');
	}

	/**
	 * Checks is photo comment
	 *
	 * @return {boolean}
	 */
	get isPhotoComment() {
		return this.includesFromSubType('photo');
	}

	/**
	 * Checks is wall comment
	 *
	 * @return {boolean}
	 */
	get isWallComment() {
		return this.includesFromSubType('wall');
	}

	/**
	 * Checks is video comment
	 *
	 * @return {boolean}
	 */
	get isVideoComment() {
		return this.includesFromSubType('video');
	}

	/**
	 * Checks is board comment
	 *
	 * @return {boolean}
	 */
	get isBoardComment() {
		return this.includesFromSubType('board');
	}

	/**
	 * Checks is board comment
	 *
	 * @return {boolean}
	 */
	get isMarketComment() {
		return this.includesFromSubType('market');
	}

	/**
	 * Checks is reply comment
	 *
	 * @return {boolean}
	 */
	get isReply() {
		return 'reply_to_comment' in this.payload;
	}

	/**
	 * Returns the identifier comment
	 *
	 * @return {number}
	 */
	get id() {
		return this.payload.id;
	}

	/**
	 * Returns the identifier reply comment
	 *
	 * @return {?number}
	 */
	get replyId() {
		return this.payload.reply_to_comment || null;
	}

	/**
	 * Returns the identifier user
	 *
	 * @return {?number}
	 */
	get userId() {
		return (
			this.payload.from_id
			|| this.payload.user_id
			|| null
		);
	}

	/**
	 * Returns the identifier reply user
	 *
	 * @return {?number}
	 */
	get replyUserId() {
		return this.payload.reply_to_user || null;
	}

	/**
	 * Returns the identifier of the user who deleted the comment
	 *
	 * @return {?number}
	 */
	get removerUserId() {
		return this.payload.deleter_id || null;
	}

	/**
	 * Returns the identifier of object
	 *
	 * @return {?number}
	 */
	get objectId() {
		const { payload } = this;

		return (
			payload.photo_id
			|| payload.video_id
			|| payload.post_id
			|| payload.topic_id
			|| payload.item_id
			|| null
		);
	}

	/**
	 * Returns the identifier of owner
	 *
	 * @return {?number}
	 */
	get ownerId() {
		const { payload } = this;

		return (
			payload.owner_id
			|| payload.photo_owner_id
			|| payload.video_owner_id
			|| payload.post_owner_id
			|| payload.topic_owner_id
			|| payload.market_owner_id
			|| null
		);
	}

	/**
	 * Returns the date creation action comment
	 *
	 * @return {?number}
	 */
	get createdAt() {
		return this.payload.date || null;
	}

	/**
	 * Returns the text comment
	 *
	 * @return {?string}
	 */
	get text() {
		return this.payload.text || null;
	}

	/**
	 * Returns the likes
	 *
	 * @return {?Object}
	 */
	get likes() {
		return this.payload.likes || null;
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Includes from subtype
	 *
	 * @param {string} type
	 *
	 * @return {string}
	 */
	includesFromSubType(type) {
		return this.subTypes[1].includes(type);
	}

	/**
	 * Edits a comment
	 *
	 * @param {Object} options
	 *
	 * @return {Promise}
	 */
	editComment(options) {
		if (this.isDelete) {
			return Promise.reject(new VKError({
				message: 'Comment is deleted'
			}));
		}

		if (this.isBoardComment) {
			return this.vk.api.board.editComment({
				...options,

				comment_id: this.id,
				topic_id: this.objectId,
				group_id: this.$groupId
			});
		}

		const params = {
			...options,

			comment_id: this.id,
			owner_id: this.ownerId
		};

		if (this.isPhotoComment) {
			return this.vk.api.photos.editComment(params);
		}

		if (this.isVideoComment) {
			return this.vk.api.video.editComment(params);
		}

		if (this.isWallComment) {
			return this.vk.api.wall.editComment(params);
		}

		if (this.isMarketComment) {
			return this.vk.api.market.editComment(params);
		}

		return Promise.reject(new VKError({
			message: 'Unsupported event for editing comment'
		}));
	}

	/**
	 * Removes comment
	 *
	 * @return {Promise}
	 */
	deleteComment() {
		if (this.isDelete) {
			return Promise.reject(new VKError({
				message: 'Comment is deleted'
			}));
		}

		if (this.isBoardComment) {
			return this.vk.api.board.deleteComment({
				comment_id: this.id,
				topic_id: this.objectId,
				group_id: this.$groupId
			});
		}

		const params = {
			comment_id: this.id,
			owner_id: this.ownerId
		};

		if (this.isPhotoComment) {
			return this.vk.api.photos.deleteComment(params);
		}

		if (this.isVideoComment) {
			return this.vk.api.video.deleteComment(params);
		}

		if (this.isWallComment) {
			return this.vk.api.wall.deleteComment(params);
		}

		if (this.isMarketComment) {
			return this.vk.api.market.deleteComment(params);
		}

		return Promise.reject(new VKError({
			message: 'Unsupported event for deleting comment'
		}));
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		const properties = [
			'id',
			'replyId',
			'userId',
			'replyUserId',
			'removerUserId',
			'objectId',
			'ownerId',
			'createdAt',
			'text',
			'likes',
			'attachments',
			'isReply'
		];

		const filtredEmptyProperties = properties.filter(property => (
			this[property] !== null
		));

		return copyParams(this, filtredEmptyProperties);
	}
}

const subTypes$9 = {
	photo_new: ['new_photo_attachment', PhotoAttachment],
	video_new: ['new_video_attachment', VideoAttachment],
	audio_new: ['new_audio_attachment', AudioAttachment]
};

class NewAttachmentsContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Object} payload
	 * @param {Object} options
	 */
	constructor(vk, payload, { updateType, groupId }) {
		super(vk);

		this.payload = payload;
		this.$groupId = groupId;

		const [subType, Attachment] = subTypes$9[updateType];

		this.attachments = [new Attachment(payload, vk)];

		this.type = 'new_attachment';
		this.subTypes = [subType];
	}

	/**
	 * Checks is attachment photo
	 *
	 * @return {boolean}
	 */
	get isPhoto() {
		return this.subTypes.includes('new_photo_attachment');
	}

	/**
	 * Checks is attachment video
	 *
	 * @return {boolean}
	 */
	get isVideo() {
		return this.subTypes.includes('new_video_attachment');
	}

	/**
	 * Checks is attachment audio
	 *
	 * @return {boolean}
	 */
	get isAudio() {
		return this.subTypes.includes('new_audio_attachment');
	}

	/**
	 * Checks for the presence of attachments
	 *
	 * @param {?string} type
	 *
	 * @return {boolean}
	 */
	hasAttachments(type = null) {
		if (type === null) {
			return this.attachments.length > 0;
		}

		return this.attachments.some(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Returns the attachments
	 *
	 * @param {?string} type
	 *
	 * @return {Array}
	 */
	getAttachments(type = null) {
		if (type === null) {
			return this.attachments;
		}

		return this.attachments.filter(attachment => (
			attachment.type === type
		));
	}

	/**
	 * Removes the attachment
	 *
	 * @return {Promise}
	 */
	deleteAttachment() {
		if (this.isPhoto) {
			const [photo] = this.getAttachments('photo');

			return this.vk.api.photos.delete({
				owner_id: photo.ownerId,
				photo_id: photo.id
			});
		}

		if (this.isVideo) {
			const [video] = this.getAttachments('video');

			return this.vk.api.video.delete({
				owner_id: video.ownerId,
				video_id: video.id
			});
		}

		if (this.isAudio) {
			const [audio] = this.getAttachments('audio');

			return this.vk.api.audio.delete({
				owner_id: audio.ownerId,
				audio_id: audio.id
			});
		}

		return Promise.reject(new VKError({
			message: 'Unsupported event for deleting attachment'
		}));
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'attachments',
			'isPhoto',
			'isVideo',
			'isAudio'
		]);
	}
}

const subTypes$a = {
	13: 'delete_messages',
	14: 'restore_messages'
};

class RemovedMessagesContext extends Context {
	/**
	 * Constructor
	 *
	 * @param {VK}     vk
	 * @param {Arrray} payload
	 * @param {Object} options
	 */
	constructor(vk, [eventId, peerId, id]) {
		super(vk);

		this.payload = {
			peer_id: peerId,
			id
		};

		this.type = 'removed_messages';
		this.subTypes = [
			subTypes$a[eventId]
		];
	}

	/**
	 * Checks that messages have been deleted
	 *
	 * @return {boolean}
	 */
	get isRemoved() {
		return this.subTypes.includes('delete_messages');
	}

	/**
	 * Checks that messages have been restored
	 *
	 * @return {boolean}
	 */
	get isRecovery() {
		return this.subTypes.includes('restore_messages');
	}

	/**
	 * Returns the identifier of the message
	 *
	 * @return {string}
	 */
	get id() {
		return this.payload.id;
	}

	/**
	 * Returns the peer ID
	 *
	 * @return {number}
	 */
	get peerId() {
		return this.payload.peer_id;
	}

	/**
	 * Returns the custom data
	 *
	 * @type {Object}
	 */
	[inspectCustomData]() {
		return copyParams(this, [
			'id',
			'peerId',
			'isRemoved',
			'isRecovery'
		]);
	}
}

const splitPath = (path) => (
	path
		.replace(/\[([^[\]]*)\]/g, '.$1.')
		.split('.')
		.filter(Boolean)
);

const getObjectValue = (source, selectors) => {
	let link = source;

	for (const selector of selectors) {
		if (!link[selector]) {
			return undefined;
		}

		link = link[selector];
	}

	return link;
};

const unifyCondition = (condition) => {
	if (typeof condition === 'function') {
		return condition;
	}

	if (condition instanceof RegExp) {
		return text => (
			condition.test(text)
		);
	}

	if (Array.isArray(condition)) {
		const arrayConditions = condition.map(unifyCondition);

		return value => (
			Array.isArray(value)
				? arrayConditions.every(cond => (
					value.some(val => cond(val))
				))
				: arrayConditions.some(cond => (
					cond(value)
				))
		);
	}

	return value => value === condition;
};

const parseRequestJSON = (req, res) => (
	new Promise((resolve, reject) => {
		let body = '';

		req.on('error', reject);
		req.on('data', (chunk) => {
			if (body.length > 1e6) {
				body = null;

				res.writeHead(413);
				res.end();

				req.connection.destroy();

				reject();

				return;
			}

			body += String(chunk);
		});

		req.on('end', () => {
			try {
				const json = JSON.parse(body);

				resolve(json);
			} catch (e) {
				reject(e);
			}
		});
	})
);

const { URL: URL$6, URLSearchParams: URLSearchParams$6 } = nodeUrl;
const { inspect: inspect$c, promisify: promisify$2 } = nodeUtil;

const { NEED_RESTART, POLLING_REQUEST_FAILED } = updatesErrors;

const debug$8 = createDebug('vk-io:updates');

/**
 * Version polling
 *
 * @type {number}
 */
const POLLING_VERSION = 3;

const webhookContextsEvents = [
	[
		['message_new', 'message_edit', 'message_reply'],
		MessageContext
	],
	[
		['message_allow', 'message_deny'],
		MessageAllowContext
	],
	[
		['photo_new', 'audio_new', 'video_new'],
		NewAttachmentsContext
	],
	[
		['wall_post_new', 'wall_repost'],
		WallPostContext
	],
	[
		['group_join', 'group_leave'],
		GroupMemberContext
	],
	[
		['user_block', 'user_unblock'],
		GroupUserContext
	],
	[
		[
			'photo_comment_new',
			'photo_comment_edit',
			'photo_comment_delete',
			'photo_comment_restore',
			'video_comment_new',
			'video_comment_edit',
			'video_comment_delete',
			'video_comment_restore',
			'wall_reply_new',
			'wall_reply_edit',
			'wall_reply_delete',
			'wall_reply_restore',
			'board_post_new',
			'board_post_edit',
			'board_post_delete',
			'board_post_restore',
			'market_comment_new',
			'market_comment_edit',
			'market_comment_delete',
			'market_comment_restore'
		],
		CommentActionContext
	],
	[
		['poll_vote_new'],
		VoteContext
	],
	[
		['group_change_photo', 'group_officers_edit', 'group_change_settings'],
		GroupUpdateContext
	],
	[
		['message_typing_state'],
		TypingContext
	]
];

const pollingContextsEvents = [
	[
		[1, 2, 3],
		MessageFlagsContext
	],
	[
		[4, 5],
		MessageContext
	],
	[
		[6, 7],
		ReadMessagesContext
	],
	[
		[8, 9],
		UserOnlineContext
	],
	[
		[10, 11, 12],
		DialogFlagsContext
	],
	[
		[13, 14],
		RemovedMessagesContext
	],
	[
		[61, 62],
		TypingContext
	]
];

const makeContexts = (groups) => {
	const contexts = {};

	for (const [events, Context] of groups) {
		for (const event of events) {
			contexts[event] = Context;
		}
	}

	return contexts;
};

const webhookContexts = makeContexts(webhookContextsEvents);
const pollingContexts = makeContexts(pollingContextsEvents);

class Updates {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.restarted = 0;
		this.started = null;

		this.url = null;

		this.ts = null;
		this.pts = null;

		/**
		 * 2 -  Attachments
		 * 8 -  Extended events
		 * 64 - Online user platform ID
		 *
		 * @type {number}
		 */
		this.mode = 2 | 8 | 64;

		this.webhookServer = null;

		this.stack = [];
		this.hearStack = [];

		this.hearFallbackHandler = (context, next) => next();

		this.reloadMiddleware();
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'Updates';
	}

	/**
	 * Checks is started
	 *
	 * @return {boolean}
	 */
	get isStarted() {
		return this.started !== null;
	}

	/**
	 * Added middleware
	 *
	 * @param {Function} handler
	 *
	 * @return {this}
	 */
	use(middleware) {
		if (typeof middleware !== 'function') {
			throw new VKError({
				message: 'Middleware must be a function'
			});
		}

		this.stack.push(middleware);

		this.reloadMiddleware();

		return this;
	}

	/**
	 * Subscribe to events
	 *
	 * @param {string[]} events
	 * @param {Function} handler
	 *
	 * @return {this}
	 */
	on(events, handler) {
		if (!Array.isArray(events)) {
			events = [events];
		}

		const hasEvents = events.every(Boolean);

		if (!hasEvents) {
			throw new VKError({
				message: 'Events should be not empty'
			});
		}

		if (typeof handler !== 'function') {
			throw new VKError({
				message: 'Handler must be a function'
			});
		}

		return this.use((context, next) => (
			context.is(events)
				? handler(context, next)
				: next()
		));
	}

	/**
	 * Listen text
	 *
	 * @param {*[]}      rawConditions
	 * @param {Function} handler
	 *
	 * @return {this}
	 */
	hear(rawConditions, handler) {
		if (!Array.isArray(rawConditions)) {
			rawConditions = [rawConditions];
		}

		const hasConditions = rawConditions.every(Boolean);

		if (!hasConditions) {
			throw new Error('Condition should be not empty');
		}

		if (typeof handler !== 'function') {
			throw new TypeError('Handler must be a function');
		}

		let textCondition = false;
		let functionCondtion = false;
		const conditions = rawConditions.map((condition) => {
			if (typeof condition === 'object' && !(condition instanceof RegExp)) {
				functionCondtion = true;

				const entries = Object.entries(condition).map(([path, value]) => (
					[splitPath(path), unifyCondition(value)]
				));

				return (text, context) => (
					entries.every(([selectors, callback]) => {
						const value = getObjectValue(context, selectors);

						return callback(value, context);
					})
				);
			}

			if (typeof condition === 'function') {
				functionCondtion = true;

				return condition;
			}

			textCondition = true;

			if (condition instanceof RegExp) {
				return (text, context) => {
					const passed = condition.test(text);

					if (passed) {
						context.$match = text.match(condition);
					}

					return passed;
				};
			}

			condition = String(condition);

			return text => text === condition;
		});

		const needText = textCondition === true && functionCondtion === false;

		this.hearStack.push((context, next) => {
			const { text } = context;

			if (needText && text === null) {
				return next();
			}

			const hasSome = conditions.some(condition => (
				condition(text, context)
			));

			return hasSome
				? handler(context, next)
				: next();
		});

		this.reloadMiddleware();

		return this;
	}

	/**
	 * A handler that is called when handlers are not found
	 *
	 * @param {Function} handler
	 *
	 * @return {this}
	 */
	setHearFallbackHandler(handler) {
		this.hearFallbackHandler = handler;

		return this;
	}

	/**
	 * Handles longpoll event
	 *
	 * @param {Array} update
	 *
	 * @return {Promise}
	 */
	handlePollingUpdate(update) {
		debug$8('longpoll update', update);

		const { 0: type } = update;

		const Context = pollingContexts[type];

		if (!Context) {
			debug$8(`Unsupported polling context type ${type}`);

			return Promise.resolve();
		}

		return this.dispatchMiddleware(new Context(this.vk, update, {
			source: updatesSources.POLLING,

			updateType: type
		}));
	}

	/**
	 * Handles webhook event
	 *
	 * @param {Object} update
	 *
	 * @return {Promise}
	 */
	handleWebhookUpdate(update) {
		debug$8('webhook update', update);

		const { type, object: payload, group_id: groupId } = update;

		const Context = webhookContexts[type];

		if (!Context) {
			debug$8(`Unsupported webhook context type ${type}`);

			return Promise.resolve();
		}

		return this.dispatchMiddleware(new Context(this.vk, payload, {
			source: updatesSources.WEBHOOK,

			updateType: type,
			groupId
		}));
	}

	/**
	 * Starts to poll server
	 *
	 * @return {Promise}
	 */
	async startPolling() {
		if (this.isStarted) {
			debug$8(`Updates already started: ${this.started}`);

			return;
		}

		this.started = 'polling';

		try {
			const { pollingGroupId } = this.vk.options;

			const isGroup = pollingGroupId !== null;

			const { server, key, ts } = isGroup
				? await this.vk.api.groups.getLongPollServer({
					group_id: pollingGroupId
				})
				: await this.vk.api.messages.getLongPollServer({
					lp_version: POLLING_VERSION
				});

			this.pollingHandler = isGroup
				? this.handleWebhookUpdate.bind(this)
				: this.handlePollingUpdate.bind(this);

			if (this.ts === null) {
				this.ts = ts;
			}

			const pollingURL = isGroup
				? server
				: `https://${server}`;

			this.url = new URL$6(pollingURL);
			this.url.search = new URLSearchParams$6({
				key,
				act: 'a_check',
				wait: 25,
				mode: this.mode,
				version: POLLING_VERSION
			});

			this.startFetchLoop();

			debug$8(`${isGroup ? 'Bot' : 'User'} Polling started`);
		} catch (error) {
			this.started = null;

			throw error;
		}
	}

	/**
	 * Starts the webhook server
	 *
	 * @param {Function} next
	 *
	 * @return {Promise}
	 */
	async startWebhook(
		{
			path = '/',

			tls,
			host,
			port
		} = {},
		next
	) {
		if (this.isStarted) {
			debug$8(`Updates already started: ${this.started}`);

			return;
		}

		this.started = 'webhook';

		try {
			const webhookCallback = this.getWebhookCallback(path);

			const callback = typeof next === 'function'
				? (req, res) => (
					webhookCallback(req, res, () => (
						next(req, res)
					))
				)
				: (req, res) => (
					webhookCallback(req, res, () => {
						res.writeHead(403);
						res.end();
					})
				);

			this.webhookServer = tls
				? nodeHttps.createServer(tls, callback)
				: nodeHttp.createServer(callback);

			if (!port) {
				port = tls
					? 443
					: 80;
			}

			const { webhookServer } = this;

			const listen = promisify$2(webhookServer.listen).bind(webhookServer);

			await listen(port, host);

			debug$8(`Webhook listening on port: ${port}`);
		} catch (error) {
			this.started = null;

			throw error;
		}
	}

	/**
	 * Automatically determines the settings to run
	 *
	 * @return {Promise}
	 */
	async start({ webhook } = {}) {
		if (webhook) {
			await this.startWebhook(webhook);

			return;
		}

		if (!this.vk.options.pollingGroupId) {
			try {
				const [group] = await this.vk.api.groups.getById();

				this.vk.options.pollingGroupId = group.id;
			} catch (error) {
				if (error.code !== apiErrors.WRONG_PARAMETER) {
					throw error;
				}

				debug$8('This is not a group.');
			}
		}

		await this.startPolling();
	}

	/**
	 * Stopping gets updates
	 *
	 * @return {Promise}
	 */
	async stop() {
		this.started = null;

		this.restarted = 0;

		if (this.webhookServer !== null) {
			const { webhookServer } = this;

			const close = promisify$2(webhookServer.close).bind(webhookServer);

			await close();

			this.webhookServer = null;
		}
	}

	/**
	 * Returns webhook callback like http[s] or express
	 *
	 * @param {string} path
	 *
	 * @return {Function}
	 */
	getWebhookCallback(path = null) {
		const headers = {
			connection: 'keep-alive',
			'content-type': 'text/plain'
		};

		const checkIsNotValidPath = path !== null
			? requestPath => requestPath !== path
			: () => false;

		return async (req, res, next) => {
			if (req.method !== 'POST' || checkIsNotValidPath(req.url)) {
				next();

				return;
			}

			let update;
			try {
				update = typeof req.body !== 'object'
					? await parseRequestJSON(req, res)
					: req.body;
			} catch (e) {
				debug$8(e);

				return;
			}

			try {
				const { webhookSecret, webhookConfirmation } = this.vk.options;

				if (webhookSecret !== null && update.secret !== webhookSecret) {
					res.writeHead(403);
					res.end();

					return;
				}

				if (update.type === 'confirmation') {
					if (webhookConfirmation === null) {
						res.writeHead(500);
						res.end();

						return;
					}

					res.writeHead(200, headers);
					res.end(String(webhookConfirmation));

					return;
				}

				res.writeHead(200, headers);
				res.end('ok');

				this.handleWebhookUpdate(update).catch((error) => {
					// eslint-disable-next-line no-console
					console.error('Handle webhook update error', error);
				});
			} catch (error) {
				debug$8('webhook error', error);

				res.writeHead(415);
				res.end();
			}
		};
	}

	/**
	 * Returns the middleware for the webhook under koa
	 *
	 * @param {Object} options
	 *
	 * @return {Function}
	 */
	getKoaWebhookMiddleware() {
		return async (context) => {
			const update = context.request.body;

			const { webhookSecret, webhookConfirmation } = this.vk.options;

			if (webhookSecret !== null && update.secret !== webhookSecret) {
				context.status = 403;

				return;
			}

			if (update.type === 'confirmation') {
				if (webhookConfirmation === null) {
					context.status = 500;

					return;
				}

				context.body = webhookConfirmation;

				return;
			}

			context.body = 'ok';
			context.set('connection', 'keep-alive');

			/* Do not delay server response */
			this.handleWebhookUpdate(update).catch((error) => {
				// eslint-disable-next-line no-console
				console.error('Handle webhook update error', error);
			});
		};
	}

	/**
	 * Starts forever fetch updates  loop
	 *
	 * @return {Promise}
	 */
	async startFetchLoop() {
		try {
			while (this.started === 'polling') {
				await this.fetchUpdates();
			}
		} catch (error) {
			debug$8('longpoll error', error);

			const { pollingWait, pollingAttempts } = this.vk.options;

			if (error.code !== NEED_RESTART && this.restarted < pollingAttempts) {
				this.restarted += 1;

				debug$8('longpoll restart request');

				await delay(3e3);

				this.startFetchLoop();

				return;
			}

			while (this.started === 'polling') {
				try {
					await this.stop();
					await this.startPolling();

					break;
				} catch (restartError) {
					debug$8('longpoll restarted error', restartError);

					this.started = 'polling';

					await delay(pollingWait);
				}
			}
		}
	}

	/**
	 * Gets updates
	 *
	 * @return {Promise}
	 */
	async fetchUpdates() {
		this.url.searchParams.set('ts', this.ts);

		debug$8('http -->');

		let response = await fetch(this.url, {
			agent: this.vk.options.agent,
			method: 'GET',
			timeout: 30e3,
			compress: false,
			headers: {
				connection: 'keep-alive'
			}
		});

		debug$8(`http <-- ${response.status}`);

		if (!response.ok) {
			throw new UpdatesError({
				code: POLLING_REQUEST_FAILED,
				message: 'Polling request failed'
			});
		}

		response = await response.json();

		if ('failed' in response) {
			if (response.failed === 1) {
				this.ts = response.ts;

				return;
			}

			this.ts = null;

			throw new UpdatesError({
				code: NEED_RESTART,
				message: 'The server has failed'
			});
		}

		this.restarted = 0;
		this.ts = response.ts;

		if ('pts' in response) {
			this.pts = Number(response.pts);
		}

		/* Async handle updates */
		response.updates.forEach(async (update) => {
			try {
				await this.pollingHandler(update);
			} catch (error) {
				// eslint-disable-next-line no-console
				console.error('Handle polling update error:', error);
			}
		});
	}

	/**
	 * Calls up the middleware chain
	 *
	 * @param {Context} context
	 *
	 * @return {Promise<void>}
	 */
	dispatchMiddleware(context) {
		return this.stackMiddleware(context, noopNext);
	}

	/**
	 * Reloads middleware
	 */
	reloadMiddleware() {
		const stack = [...this.stack];

		if (this.hearStack.length !== 0) {
			stack.push(
				getOptionalMiddleware(
					context => context.type === 'message' && !context.isEvent,
					compose([
						...this.hearStack,
						this.hearFallbackHandler
					])
				)
			);
		}

		this.stackMiddleware = compose(stack);
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$c.custom](depth, options) {
		const { name } = this.constructor;

		const { started, stack } = this;

		const payload = { started, stack };

		return `${options.stylize(name, 'special')} ${inspect$c(payload, options)}`;
	}
}

const { URL: URL$7 } = nodeUrl;

const {
	INVALID_URL,
	INVALID_RESOURCE,
	RESOURCE_NOT_FOUND
} = snippetsErrors;

const numberRe = /^-?\d+$/;

const hasProtocolRe = /https?:\/\//i;
const isVKUrl = /^(?:https?:\/\/)?(?:m\.)?vk\.com/i;

const isUserMentionRe = /\*|@/;
const systemMentionRe = /\[([^|]+)|([^|\]]+)\]/;

/**
 * Switch resource types
 *
 * @type {Object}
 */
const enumResourceTypes = {
	id: resourceTypes.USER,
	club: resourceTypes.GROUP,
	public: resourceTypes.GROUP,
	app: resourceTypes.APPLICATION
};

/**
 * Remove search param
 *
 * @type {RegExp}
 */
const removeSearchParam = /(\?|&)[^=]+=/;

/**
 * Resolve the attachment resource
 *
 * @param {string} resource
 * @param {RegExp} pattern
 *
 * @return {Object}
 */
const resolveOwnerResource = (resource, pattern) => {
	const {
		1: type,
		2: owner,
		3: id
	} = resource.match(pattern);

	return {
		id: Number(id),
		owner: Number(owner),
		type: type.toLowerCase().replace(removeSearchParam, '')
	};
};

class ResourceResolver {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;
	}

	/**
	 * Resolve resource
	 *
	 * @return {Promise<Object>}
	 */
	async resolve(resource) {
		if (!resource) {
			throw new SnippetsError({
				code: INVALID_RESOURCE,
				message: 'Resource is required'
			});
		}

		resource = String(resource).trim();

		if (numberRe.test(resource)) {
			return this.resolveNumber(resource);
		}

		const isMention = (
			isUserMentionRe.test(resource) || systemMentionRe.test(resource)
		);

		if (isMention) {
			return this.resolveMention(resource);
		}

		if (isVKUrl.test(resource)) {
			return this.resolveUrl(resource);
		}

		return this.resolveScreenName(resource);
	}

	/**
	 * Resolve number
	 *
	 * @param {string} resource
	 *
	 * @return {Promise<Object>}
	 */
	resolveNumber(resource) {
		const isGroup = resource < 0;

		const type = isGroup
			? 'club'
			: 'id';

		return this.resolveScreenName(type + (
			isGroup
				? -resource
				: resource
		));
	}

	/**
	 * Resolve resource mention
	 *
	 * @param {string} resource
	 *
	 * @return {Promise<Object>}
	 */
	resolveMention(resource) {
		if (isUserMentionRe.test(resource)) {
			return this.resolveScreenName(resource.substring(1));
		}

		const { 1: mentionResource } = resource.match(systemMentionRe);

		return this.resolveScreenName(mentionResource);
	}

	/**
	 * Resolve resource url
	 *
	 * @param {string} resource
	 *
	 * @return {Promise<Object>}
	 */
	async resolveUrl(resourceUrl) {
		if (!hasProtocolRe.test(resourceUrl)) {
			resourceUrl = `https://${resourceUrl}`;
		}

		const { pathname, search } = new URL$7(resourceUrl);

		if (pathname === '/') {
			throw new SnippetsError({
				code: INVALID_URL,
				message: 'URL should contain path'
			});
		}

		if (parseAttachment.test(search)) {
			return resolveOwnerResource(search, parseAttachment);
		}

		if (parseOwnerResource.test(search)) {
			return resolveOwnerResource(search, parseOwnerResource);
		}

		return this.resolveScreenName(pathname.substring(1));
	}

	/**
	 * Resolve screen name
	 *
	 * @param {string} resource
	 *
	 * @return {Promise<Object>}
	 */
	async resolveScreenName(resource) {
		if (parseAttachment.test(resource)) {
			return resolveOwnerResource(resource, parseAttachment);
		}

		if (parseOwnerResource.test(resource)) {
			return resolveOwnerResource(resource, parseOwnerResource);
		}

		if (parseResource.test(resource)) {
			const { 1: typeResource, 2: id } = resource.match(parseResource);

			let type = typeResource.toLowerCase();

			if (type in enumResourceTypes) {
				type = enumResourceTypes[type];
			}

			return {
				id: Number(id),
				type
			};
		}

		const response = await this.vk.api.utils.resolveScreenName({
			screen_name: resource
		});

		if (Array.isArray(response)) {
			throw new SnippetsError({
				message: 'Resource not found',
				code: RESOURCE_NOT_FOUND
			});
		}

		const { type, object_id: id } = response;

		if (type === 'page') {
			return {
				id,
				type: resourceTypes.GROUP
			};
		}

		return { id, type };
	}
}

class Snippets {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.resourceResolver = new ResourceResolver(this.vk);
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'Snippets';
	}

	/**
	 * Defines the type of object (user, community, application, attachment)
	 *
	 * @param {*} resource
	 *
	 * @return {Promise<Object>}
	 */
	resolveResource(resource) {
		return this.resourceResolver.resolve(resource);
	}
}

const { URL: URL$8, URLSearchParams: URLSearchParams$7 } = nodeUrl;
const { inspect: inspect$d, promisify: promisify$3 } = nodeUtil;

const debug$9 = createDebug('vk-io:streaming');

class StreamingAPI {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.key = null;
		this.socket = null;
		this.endpoint = null;

		this.started = null;
		this.handlers = [];
	}

	/**
	 * Returns custom tag
	 *
	 * @return {string}
	 */
	get [Symbol.toStringTag]() {
		return 'StreamingAPI';
	}

	/**
	 * Starts websocket
	 *
	 * @return {Promise}
	 */
	async startWebSocket() {
		this.started = 'websocket';

		try {
			const { key, endpoint } = await this.vk.api.streaming.getServerUrl();

			this.key = key;
			this.endPoint = new URL$8(`https://${endpoint}`);

			const search = new URLSearchParams$7({ key });

			const { agent } = this.vk.options;

			this.socket = new WebSocket(`wss://${endpoint}/stream?${search}`, { agent });
		} catch (error) {
			this.started = null;

			throw error;
		}

		const { socket } = this;

		this.close = promisify$3(socket.close).bind(socket);

		socket.on('message', async (data) => {
			let message;

			try {
				message = JSON.parse(data);
			} catch (error) {
				debug$9('JSON parse failed', error);

				return;
			}

			const { code } = message;

			try {
				switch (code) {
					case 100: {
						await this.handleEvent(message.event);

						break;
					}

					case 300: {
						await this.handleServiceMessage(message.service_message);

						break;
					}

					default: {
						debug$9(`Unsupported message code: ${code}`);
					}
				}
			} catch (error) {
				// eslint-disable-next-line no-console
				console.log('Handle event error', error);
			}
		});

		socket.on('error', (error) => {
			debug$9('WebSocket error', error);
		});
	}

	/**
	 * Stop all connection
	 *
	 * @return {Promise}
	 */
	async stop() {
		if (this.started === null) {
			return;
		}

		await this.close();

		this.started = null;

		this.key = null;
		this.socket = null;
		this.endpoint = null;
	}

	/**
	 * Processes server messages
	 *
	 * @param {Object} serviceMessage
	 *
	 * @return {Promise}
	 */
	async handleServiceMessage({ service_code: code }) {
		if ([3000, 3001].includes(code)) {
			await this.stop();
			await this.start();
		}
	}

	/**
	 * Handles events
	 *
	 * @param {Object} event
	 *
	 * @return {Promise}
	 */
	handleEvent(event) {
		const context = new StreamingContext(this.vk, event);

		return this.vk.updates.dispatchMiddleware(context);
	}

	/**
	 * Executes the HTTP request for rules
	 *
	 * @param {string} method
	 * @param {Object} options
	 *
	 * @return {Promise<Object>}
	 */
	async fetchRules(method, payload = {}) {
		const { agent } = this.vk.options;

		const url = new URL$8('/rules', this.endPoint);
		url.searchParams.set('key', this.key);

		let body;
		if (method !== 'GET') {
			body = JSON.stringify(payload);
		}

		let response = await fetch(url, {
			agent,
			method,
			body,
			headers: {
				'content-type': 'application/json'
			}
		});
		response = await response.json();

		if ('error' in response) {
			throw new StreamingRuleError(response.error);
		}

		return response;
	}

	/**
	 * Returns a list of rules
	 *
	 * @return {Promise<Array>}
	 */
	async getRules() {
		const { rules = [] } = await this.fetchRules('GET');

		return rules;
	}

	/**
	 * Adds a rule
	 *
	 * @param {Object} rule
	 *
	 * @return {Promise}
	 */
	addRule(rule) {
		return this.fetchRules('POST', { rule });
	}

	/**
	 * Removes the rule
	 *
	 * @param {string} tag
	 *
	 * @return {Promise}
	 */
	deleteRule(tag) {
		return this.fetchRules('DELETE', { tag });
	}

	/**
	 * Adds a list of rules
	 *
	 * @param {Array} rules
	 *
	 * @return {Promise}
	 */
	addRules(rules) {
		return Promise.all(rules.map(rule => (
			this.addRule(rule)
		)));
	}

	/**
	 * Removes all rules
	 *
	 * @return {Promise}
	 */
	async deleteRules() {
		const rules = await this.getRules();

		const response = await Promise.all(rules.map(({ tag }) => (
			this.deleteRule(tag)
		)));

		return response;
	}

	/**
	 * Custom inspect object
	 *
	 * @param {?number} depth
	 * @param {Object}  options
	 *
	 * @return {string}
	 */
	[inspect$d.custom](depth, options) {
		const { name } = this.constructor;

		const { started, handlers } = this;

		const payload = { started, handlers };

		return `${options.stylize(name, 'special')} ${inspect$d(payload, options)}`;
	}
}

const {
	MISSING_CAPTCHA_HANDLER,
	MISSING_TWO_FACTOR_HANDLER
} = sharedErrors;

class CallbackService {
	/**
	 * Constructor
	 *
	 * @param {VK} vk
	 */
	constructor(vk) {
		this.vk = vk;

		this.captchaHandler = null;
		this.twoFactorHandler = null;
	}

	/**
	 * Checks if there is a captcha handler
	 *
	 * @return {boolean}
	 */
	get hasCaptchaHandler() {
		return this.captchaHandler !== null;
	}

	/**
	 * Checks if there is a two-factor handler
	 *
	 * @return {boolean}
	 */
	get hasTwoFactorHandler() {
		return this.twoFactorHandler !== null;
	}

	/**
	 * Processing captcha
	 *
	 * @param {Object} payload
	 *
	 * @return {Promise<Object>}
	 */
	processingCaptcha(payload) {
		return new Promise((resolveProcessing, rejectProcessing) => {
			if (!this.hasCaptchaHandler) {
				rejectProcessing(new VKError({
					message: 'Missing captcha handler',
					code: MISSING_CAPTCHA_HANDLER
				}));

				return;
			}

			this.captchaHandler(payload, key => (
				new Promise((resolve, reject) => {
					if (key instanceof Error) {
						reject(key);
						rejectProcessing(key);

						return;
					}

					resolveProcessing({
						key,
						validate: {
							resolve,
							reject
						}
					});
				})
			));
		});
	}

	/**
	 * Processing two-factor
	 *
	 * @param {Object} payload
	 *
	 * @return {Promise<Object>}
	 */
	processingTwoFactor(payload) {
		return new Promise((resolveProcessing, rejectProcessing) => {
			if (!this.hasTwoFactorHandler) {
				rejectProcessing(new VKError({
					message: 'Missing two-factor handler',
					code: MISSING_TWO_FACTOR_HANDLER
				}));

				return;
			}

			this.twoFactorHandler(payload, code => (
				new Promise((resolve, reject) => {
					if (code instanceof Error) {
						reject(code);
						rejectProcessing(code);

						return;
					}

					resolveProcessing({
						code,
						validate: {
							resolve,
							reject
						}
					});
				})
			));
		});
	}
}

/**
 * Main class
 *
 * @public
 */
class VK {
    /**
     * Constructor
     */
    constructor(options = {}) {
        this.options = {
            ...defaultOptions,
            agent: new Agent({
                keepAlive: true,
                keepAliveMsecs: 10000
            })
        };
        this.api = new API(this);
        this.auth = new Auth(this);
        this.upload = new Upload(this);
        this.collect = new Collect(this);
        this.updates = new Updates(this);
        this.snippets = new Snippets(this);
        this.streaming = new StreamingAPI(this);
        this.callbackService = new CallbackService(this);
        this.setOptions(options);
    }
    /**
     * Returns custom tag
     *
     * @return {string}
     */
    get [Symbol.toStringTag]() {
        return 'VK';
    }
    /**
     * Sets options
     */
    setOptions(options) {
        Object.assign(this.options, options);
        return this;
    }
    /**
     * Sets token
     */
    set token(token) {
        this.options.token = token;
    }
    /**
     * Returns token
     */
    get token() {
        return this.options.token;
    }
    /**
     * Sets captcha handler
     *
     * ```ts
     * vk.captchaHandler = (payload, retry) => {...};
     * ```
     */
    set captchaHandler(handler) {
        this.callbackService.captchaHandler = handler;
    }
    /**
     * Sets two-factor handler
     *
     * ```ts
     * vk.twoFactorHandler = (payload, retry) => {...};
     * ```
     */
    set twoFactorHandler(handler) {
        this.callbackService.twoFactorHandler = handler;
    }
    /**
     * Custom inspect object
     *
     * @param {?number} depth
     * @param {Object}  options
     *
     * @return {string}
     */
    [inspect$e.custom](depth, options) {
        const { name } = this.constructor;
        const { api, updates, streaming } = this;
        const { appId, token, login, phone } = this.options;
        const payload = {
            options: {
                appId,
                login,
                phone,
                token
            },
            api,
            updates,
            streaming
        };
        return `${options.stylize(name, 'special')} ${inspect$e(payload, options)}`;
    }
}

/**
 * Primary colors used in the text button
 */
var ButtonColor;
(function (ButtonColor) {
    /**
     * The white button, indicates secondary action
     *
     * Hex color #FFFFFF
     */
    ButtonColor["SECONDARY"] = "secondary";
    /**
     * The blue button, indicates the main action
     *
     * Hex color #5181B8
     */
    ButtonColor["PRIMARY"] = "primary";
    /**
     * The red button, indicates a dangerous or a negative action (reject, delete, etc...)
     *
     * Hex color #E64646
     */
    ButtonColor["NEGATIVE"] = "negative";
    /**
     * The green button, indicates a agree, confirm, ...etc
     *
     * Hex color #4BB34B
     */
    ButtonColor["POSITIVE"] = "positive";
})(ButtonColor || (ButtonColor = {}));

class KeyboardBuilder {
    constructor() {
        /**
         * Does the keyboard close after pressing the button
         */
        this.isOneTime = false;
        /**
         * Rows with all buttons
         */
        this.rows = [];
        /**
         * Current row of buttons
         */
        this.currentRow = [];
    }
    /**
     * Returns custom tag
     */
    get [Symbol.toStringTag]() {
        return 'KeyboardBuilder';
    }
    /**
     * Text button, can be colored
     *
     * ```ts
     * builder.textButton({
     *  label: 'Buy a coffee',
     *  payload: {
     *   command: 'buy',
     *   item: 'coffee'
     *  },
     *  color: Keyboard.POSITIVE_COLOR
     * });
     * ```
     */
    textButton({ label, payload: rawPayload = {}, color = ButtonColor.SECONDARY }) {
        if (label.length > 40) {
            throw new RangeError('Maximum length of label 40 characters');
        }
        const payload = JSON.stringify(rawPayload);
        if (payload.length > 255) {
            throw new RangeError('Maximum length of payload 255 characters');
        }
        return this.addButton({
            color,
            action: {
                label,
                payload,
                type: 'text'
            }
        });
    }
    /**
     * User location request button, occupies the entire keyboard width
     *
     * ```ts
     * builder.locationRequestButton({
     *  payload: {
     *   command: 'order_delivery'
     *  }
     * })
     * ```
     */
    locationRequestButton({ payload: rawPayload = {} }) {
        const payload = JSON.stringify(rawPayload);
        if (payload.length > 255) {
            throw new RangeError('Maximum length of payload 255 characters');
        }
        return this.addWideButton({
            action: {
                payload,
                type: 'location'
            }
        });
    }
    /**
     * VK Pay button, occupies the entire keyboard width
     *
     * ```ts
     * builder.payButton({
     *  hash: {
     *   action: 'transfer-to-group',
     *   group_id: 1,
     *   aid: 10
     *  }
     * })
     * ```
     */
    payButton({ hash: rawHash }) {
        const hash = typeof rawHash === 'object'
            ? String(new URLSearchParams$8(Object.entries(rawHash)))
            : rawHash;
        return this.addWideButton({
            action: {
                hash,
                type: 'vkpay'
            }
        });
    }
    /**
     * VK Apps button, occupies the entire keyboard width
     *
     * ```ts
     * builder.applicationButton({
     *  label: 'LiveWidget',
     *  appId: 6232540,
     *  ownerId: -157525928
     * })
     * ```
     */
    applicationButton({ label, appId, ownerId, hash }) {
        if (label.length > 40) {
            throw new RangeError('Maximum length of label 40 characters');
        }
        return this.addWideButton({
            action: {
                label,
                hash,
                app_id: appId,
                owner_id: ownerId,
                type: 'open_app'
            }
        });
    }
    /**
     * Saves the current row of buttons in the general rows
     */
    row() {
        if (this.currentRow.length === 0) {
            return this;
        }
        if (this.currentRow.length > 4) {
            throw new RangeError('Max count of buttons at columns 4');
        }
        this.rows.push(this.currentRow);
        this.currentRow = [];
        return this;
    }
    /**
     * Sets the keyboard to close after pressing
     *
     * ```ts
     *  builder.oneTime();
     *
     *  builder.oneTime(false);
     * ```
     */
    oneTime(enabled = true) {
        this.isOneTime = enabled;
        return this;
    }
    /**
     * Clones the builder with all the settings
     */
    clone() {
        const builder = new KeyboardBuilder();
        builder.oneTime(this.isOneTime);
        builder.rows = [...this.rows];
        builder.currentRow = [...this.currentRow];
        return builder;
    }
    /**
     * Returns a string to keyboard a VK
     */
    toString() {
        if (this.rows.length > 10) {
            throw new RangeError('Max count of keyboard rows 10');
        }
        return JSON.stringify({
            one_time: this.isOneTime,
            buttons: this.currentRow.length !== 0
                ? [...this.rows, this.currentRow]
                : this.rows
        });
    }
    /**
     * Adds a button to the current row
     */
    addButton(button) {
        this.currentRow.push(button);
        return this;
    }
    /**
     * Adds a wide button to the new row
     */
    addWideButton(button) {
        if (this.currentRow.length !== 0) {
            this.row();
        }
        this.addButton(button);
        return this.row();
    }
}

class Keyboard {
    /**
     * Returns custom tag
     */
    get [Symbol.toStringTag]() {
        return 'Keyboard';
    }
    /**
     * @deprecated Use Keyboard.SECONDARY_COLOR instead
     */
    static get DEFAULT_COLOR() {
        // eslint-disable-next-line no-console
        console.log('Keyboard.DEFAULT_COLOR deprecated, use Keyboard.SECONDARY_COLOR instead');
        return ButtonColor.SECONDARY;
    }
    /**
     * The white button, indicates secondary action
     *
     * Hex color #FFFFFF
     */
    static get SECONDARY_COLOR() {
        return ButtonColor.SECONDARY;
    }
    /**
     * The blue button, indicates the main action
     *
     * Hex color #5181B8
     */
    static get PRIMARY_COLOR() {
        return ButtonColor.PRIMARY;
    }
    /**
     * The red button, indicates a dangerous or a negative action (reject, delete, etc...)
     *
     * Hex color #E64646
     */
    static get NEGATIVE_COLOR() {
        return ButtonColor.NEGATIVE;
    }
    /**
     * The green button, indicates a agree, confirm, ...etc
     *
     * Hex color #4BB34B
     */
    static get POSITIVE_COLOR() {
        return ButtonColor.POSITIVE;
    }
    /**
     * Returns keyboard builder
     */
    static builder() {
        return new KeyboardBuilder();
    }
    /**
     * Assembles a builder of buttons
     */
    static keyboard(rows) {
        const builder = new KeyboardBuilder();
        for (const row of rows) {
            const buttons = Array.isArray(row)
                ? row
                : [row];
            for (const { kind, options } of buttons) {
                if (kind === 'text') {
                    builder.textButton(options);
                    continue;
                }
                if (kind === 'location_request') {
                    builder.locationRequestButton(options);
                    continue;
                }
                if (kind === 'vk_pay') {
                    builder.payButton(options);
                    continue;
                }
                if (kind === 'vk_application') {
                    builder.applicationButton(options);
                    continue;
                }
                throw new TypeError('Unsupported type button');
            }
            builder.row();
        }
        return builder;
    }
    /**
     * Text button, can be colored
     */
    static textButton(options) {
        return { options, kind: 'text' };
    }
    /**
     * User location request button, occupies the entire keyboard width
     */
    static locationRequestButton(options) {
        return { options, kind: 'location_request' };
    }
    /**
     * VK Pay button, occupies the entire keyboard width
     */
    static payButton(options) {
        return { options, kind: 'vk_pay' };
    }
    /**
     * VK Apps button, occupies the entire keyboard width
     */
    static applicationButton(options) {
        return { options, kind: 'vk_application' };
    }
}

export default VK;
export { APIError, Attachment, AudioAttachment, AudioMessageAttachment, AuthError, ButtonColor, CollectError, CommentActionContext, Context, DialogFlagsContext, DocumentAttachment, ExecuteError, ExternalAttachment, GiftAttachment, GraffitiAttachment, GroupMemberContext, GroupUpdateContext, GroupUserContext, Keyboard, KeyboardBuilder, LinkAttachment, MarketAlbumAttachment, MarketAttachment, MessageAllowContext, MessageContext, MessageFlagsContext, NewAttachmentsContext, PhotoAttachment, PollAttachment, ReadMessagesContext, RemovedMessagesContext, Request, SnippetsError, StickerAttachment, StreamingContext, StreamingRuleError, TypingContext, UpdatesError, UploadError, UserOnlineContext, VK, VKError, VideoAttachment, VoteContext, WallAttachment, WallPostContext, WallReplyAttachment, apiErrors, attachmentTypes, authErrors, captchaTypes, collectErrors, messageSources, resourceTypes, sharedErrors, snippetsErrors, updatesErrors, uploadErrors };
