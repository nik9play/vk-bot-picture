import VKError from './error';
export interface IAPIErrorParam {
    key: string;
    value: any;
}
export interface IAPIErrorOptions {
    error_code: number;
    error_msg: string;
    request_params: IAPIErrorParam[];
    captcha_sid?: number;
    captcha_img?: string;
    redirect_uri?: string;
    confirmation_text?: string;
}
export default class APIError extends VKError {
    /**
     * Request parameters
     */
    params: IAPIErrorParam[];
    /**
     * Session identifier captcha
     */
    captchaSid?: number;
    /**
     * Image of captcha
     */
    captchaImg?: string;
    /**
     * Redirect URL, eg validation
     */
    redirectUri?: string;
    /**
     * Required confirmation text
     */
    confirmationText?: string;
    /**
     * Constructor
     */
    constructor(payload: IAPIErrorOptions);
}
