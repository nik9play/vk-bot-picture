import VKError from './error';
export interface IAuthErrorOptions {
    message: string;
    code: string;
    pageHtml?: string;
}
export default class AuthError extends VKError {
    /**
     * HTML error page
     */
    pageHtml: string | null;
    /**
     * Constructor
     */
    constructor({ message, code, pageHtml }: IAuthErrorOptions);
}
