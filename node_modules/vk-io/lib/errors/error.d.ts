declare type CopiedError = Record<string, any>;
export interface IVKErrorOptions {
    code: string | number;
    message: string;
}
/**
 * General error class
 */
export default class VKError extends Error {
    /**
     * Error code
     */
    code: string | number;
    /**
     * Constructor
     */
    constructor({ code, message }: IVKErrorOptions);
    /**
     * Returns custom tag
     */
    readonly [Symbol.toStringTag]: string;
    /**
     * Returns property for json
     */
    toJSON(): CopiedError;
}
export {};
