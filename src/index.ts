import {
  VK,
  Keyboard,
  MessageContext,
  ContextDefaultState,
  Upload,
} from "vk-io";
import _ from "lodash";

const vk = new VK({
  token: process.env.BOT_TOKEN || "",
});

const upload = new Upload({
  api: vk.api,
});

vk.updates.on("message_new", async (context) => {
  if (context.$groupId === 174060297)
    return context.send({
      message: "Используйте нового бота: https://vk.me/botsavepics2",
    });

  if (context.text == "Начать")
    return context.send({
      message: `👇 Просто отправь картинки сюда, и бот их перекинет. Бот может пересылать картинки из обычных сообщений, а так же пересланных сообщений первого уровня вложенности.`,
      keyboard: Keyboard.builder().textButton({
        label: "Начать",
        payload: {
          command: "Начать",
        },
      }),
    });

  try {
    let photosSent = false;

    if (await processPhotos(context)) {
      photosSent = true
    }

    if (context.forwards.length > 0) {
      for (const forward of context.forwards) {
        if (await processPhotos(forward)) {
          photosSent = true
        }
      }
    }

    if (!photosSent) {
      context.send(
        "❌ Я не вижу изображений. Бот может пересылать картинки из обычных сообщений, а так же пересланных сообщений первого уровня вложенности."
      );
    }
  } catch (err) {
    console.error(err);
    context.send("❌ Произошла неизвестная ошибка.");
  }
});

async function processPhotos(context: MessageContext<ContextDefaultState>) {
  const attachments = (
    await vk.api.messages.getById({
      message_ids: context.id,
    })
  ).items[0].attachments;

  if (attachments && context.hasAttachments("photo")) {
    let photoArray = [];

    photoArray = attachments
      .filter((attachment) => attachment.type === "photo")
      .map((photo) => {
        const accessKey =
          photo.photo.access_key !== undefined
            ? `_${photo.photo.access_key}`
            : "";

        return `${photo.type}${photo.photo.owner_id}_${photo.photo.id}${accessKey}`;
      });

    await context.send({
      attachment: photoArray.join(","),
    });

    // console.log(attachments[0].photo.sizes[0].url);

    // await context.send({
    //   message: '⌛ Жди...',
    // });

    // const uploadValues = attachments
    //   .filter((attachment) => attachment.type === "photo")
    //   .map((photo) => {
    //     return {
    //       value: photo.photo.sizes[0].url,
    //     };
    //   });

    // const attachmentsMsg: PhotoAttachment[] = []

    // const promises = []

    // for (const value of uploadValues) {
    //   promises.push(upload.messagePhoto({
    //     source: {
    //       values: value,
    //     },
    //   }).then(att => attachmentsMsg.push(att)))
    // }

    // await Promise.all(promises)

    // await context.send({
    //   attachment: attachmentsMsg,
    // });

    // } else if () {
    return true;
  } else {
    return false;
  }
}

vk.updates
  .start()
  .then(() => console.log("Bot started"))
  .catch(console.error);
