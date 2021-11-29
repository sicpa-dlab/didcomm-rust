import { Message, ParsedForward } from "didcomm";
import {
    MESSAGE_SIMPLE,
    FORWARD_MESSAGE,
  } from "../test-vectors";
  
  // TODO: more tests
  test.each([
    {
      case: "Not Forward",
      message: MESSAGE_SIMPLE,
    }
  ])(
    "Message.try-parse-forward handles $case",
    async ({ message }) => {
      const res = message.try_parse_forward();
      expect(res).toBeNull();
    }
  );

  test.each([
    {
      case: "Forward",
      message: FORWARD_MESSAGE,
    }
  ])(
    "Message.try-parse-forward handles $case",
    async ({ message }) => {
      const res = message.try_parse_forward();
      expect(res).toEqual(expect.anything());
    }
  );