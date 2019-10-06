import VKError from './error';
export interface IExecuteErrorOptions {
    error_code: number;
    error_msg: string;
    method: string;
}
export default class ExecuteError extends VKError {
    /**
     * The method in which the error occurred
     */
    method: string;
    /**
     * Constructor
     */
    constructor(options: IExecuteErrorOptions);
}
