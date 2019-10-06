/// <reference types="node" />
import { Readable } from 'stream';
import { SandwichStream } from 'sandwich-stream';
export declare type MultipartStreamBody = Readable | Buffer | string;
export interface IMultipartStreamAddPartOptions {
    headers?: {
        [key: string]: string;
    };
    body: MultipartStreamBody;
}
export default class MultipartStream extends SandwichStream {
    /**
     * Multipart boundary
     */
    boundary: string;
    /**
     * Constructor
     */
    constructor(boundary: string);
    /**
     * Returns custom tag
     */
    readonly [Symbol.toStringTag]: string;
    /**
     * Adds part
     */
    addPart(part: IMultipartStreamAddPartOptions): void;
    /**
     * Adds form data
     */
    append(field: string, body: MultipartStreamBody, { filename, headers }: {
        filename?: string;
        headers: IMultipartStreamAddPartOptions['headers'];
    }): void;
}
