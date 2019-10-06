/// <reference types="node" />
import { inspect } from 'util';
import API from './api';
import Auth from './auth';
import Upload from './upload';
import Collect from './collect';
import Updates from './updates';
import Snippets from './snippets';
import StreamingAPI from './streaming';
import CallbackService from './utils/callback-service';
/**
 * Main class
 *
 * @public
 */
export default class VK {
    options: any;
    api: API;
    auth: Auth;
    upload: Upload;
    collect: Collect;
    updates: Updates;
    snippets: Snippets;
    streaming: StreamingAPI;
    callbackService: CallbackService;
    /**
     * Constructor
     */
    constructor(options?: {});
    /**
     * Returns custom tag
     *
     * @return {string}
     */
    readonly [Symbol.toStringTag]: string;
    /**
     * Sets options
     */
    setOptions(options: any): this;
    /**
     * Sets token
     */
    /**
    * Returns token
    */
    token: string | null;
    /**
     * Sets captcha handler
     *
     * ```ts
     * vk.captchaHandler = (payload, retry) => {...};
     * ```
     */
    captchaHandler: any;
    /**
     * Sets two-factor handler
     *
     * ```ts
     * vk.twoFactorHandler = (payload, retry) => {...};
     * ```
     */
    twoFactorHandler: any;
    /**
     * Custom inspect object
     *
     * @param {?number} depth
     * @param {Object}  options
     *
     * @return {string}
     */
    [inspect.custom](depth: any, options: any): string;
}
